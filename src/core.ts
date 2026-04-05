import {Context, h, Logger, Session} from 'koishi';
import {randomUUID} from 'node:crypto';
import {PluginConfig} from './types';

const logger = new Logger('blacklist-online');

export const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// 全局锁：防止队列处理并发重入
let isProcessingQueue = false;

// --- 1. 权限判断 ---
export async function isUserAdmin(session: Session, config: PluginConfig, userId: string): Promise<boolean> {
    if (!session.guildId) return false;
    try {
        const member = await session.bot.getGuildMember(session.guildId, userId);
        if (!member) return false;

        // 统一转小写比对
        const allowedRoles = (config.adminRoles || ['owner', 'admin']).map(r => r.toLowerCase());
        const userRoles = [...(member.roles || [])].map(r => r.toLowerCase());

        return userRoles.some(role => allowedRoles.includes(role));
    } catch (error) {
        return false; // 报错视为无权限
    }
}

// --- 2. 同步 ---
export async function syncBlacklist(ctx: Context, config: PluginConfig): Promise<boolean> {
    try {
        const syncStartTime = performance.now();
        const meta = await ctx.database.get('blacklist_meta', {key: 'sync_revision'});
        const localRevision = meta[0]?.value || '';

        const instanceMeta = await ctx.database.get('blacklist_meta', {key: 'instance_uuid'});
        const instanceId = instanceMeta[0]?.value;

        logger.debug(`🔄 同步开始 (本地版本: ${localRevision || 'INIT'})`);

        // 发起同步请求
        // 强制使用 HTTPS 应该在 config.remoteApiUrl 配置中体现
        const response = await ctx.http.post(`${config.remoteApiUrl}/sync`, {
            revision: localRevision,
            instanceId: instanceId
        }, {
            headers: {Authorization: `Bearer ${config.apiToken}`},
            timeout: 10000
        });

        const {strategy, newRevision, data} = response;
        let hasNewEntries = false; // 标记是否有新增

        if (strategy === 'up-to-date') {
            logger.debug('✅ 黑名单已是最新');
            return false;
        }

        if (strategy === 'full_replace') {
            logger.info(`执行全量同步`);

            // 1. 先清空本地表
            await ctx.database.remove('blacklist_users', {});
            await ctx.database.remove('blacklist_whitelist', {});

            // 2. 批量写入
            // 兼容旧版API返回数组的情况（虽然我们修改了Server，但保持健壮性）
            const blacklistData = Array.isArray(data) ? data : (data.blacklist || []);
            const whitelistData = Array.isArray(data) ? [] : (data.whitelist || []);

            if (blacklistData.length > 0) {
                const batchSize = 100;
                for (let i = 0; i < blacklistData.length; i += batchSize) {
                    await ctx.database.upsert('blacklist_users', blacklistData.slice(i, i + batchSize));
                }
                hasNewEntries = true;
            }

            if (whitelistData.length > 0) {
                const batchSize = 100;
                for (let i = 0; i < whitelistData.length; i += batchSize) {
                    await ctx.database.upsert('blacklist_whitelist', whitelistData.slice(i, i + batchSize));
                }
            }

        } else if (strategy === 'incremental') {
            logger.info(`📥 增量同步 -> ${newRevision}`);

            // 处理黑名单更新
            if (data.upserts?.length) {
                await ctx.database.upsert('blacklist_users', data.upserts);
                hasNewEntries = true;
            }
            if (data.deletes?.length) {
                await ctx.database.remove('blacklist_users', {user_id: data.deletes});
            }

            // 处理白名单更新
            if (data.whitelist_upserts?.length) {
                await ctx.database.upsert('blacklist_whitelist', data.whitelist_upserts);
                // 白名单更新不视为黑名单威胁新增，不需要 hasNewEntries = true
            }
            if (data.whitelist_deletes?.length) {
                await ctx.database.remove('blacklist_whitelist', {user_id: data.whitelist_deletes});
            }
        }

        await ctx.database.upsert('blacklist_meta', [{key: 'sync_revision', value: newRevision}]);
        const syncCostMs = Math.round(performance.now() - syncStartTime);
        emitTelemetry(ctx, config, 'sync_trace', {
            strategy_used: strategy, // Tag: 'up-to-date', 'full_replace', 'incremental'
            has_new: hasNewEntries,  // Tag
            time_cost_ms: syncCostMs // Metric
        });

        logger.info('✅ 同步完成');
        return hasNewEntries;

    } catch (error: any) {
        logger.warn(`❌ 同步失败: ${error.message || error}`);
        return false;
    }
}

// --- 3. 队列入队 ---
export async function queueRequest(ctx: Context, type: 'ADD' | 'REMOVE' | 'CANCEL', payload: any) {
    const requestId = payload.requestId || randomUUID();
    payload.requestId = requestId;

    await ctx.database.create('blacklist_request_queue', {
        id: requestId,
        type,
        payload,
        createdAt: new Date(),
        retryCount: 0
    });
    return requestId;
}

// --- 4. 离线队列处理 ---
export async function processOfflineQueue(ctx: Context, config: PluginConfig) {
    if (isProcessingQueue) return; // 锁：防止重入
    isProcessingQueue = true;

    try {
        // 每次处理 10 条，避免堵塞过久
        const queue = await ctx.database.get('blacklist_request_queue', {}, {limit: 10, sort: {createdAt: 'asc'}});
        if (queue.length === 0) return;

        const instanceMeta = await ctx.database.get('blacklist_meta', {key: 'instance_uuid'});
        const instanceId = instanceMeta[0]?.value;

        logger.info(`📤 处理离线队列 (积压: ${queue.length})`);

        for (const item of queue) {
            // 死信检测：超过 5 次重试失败，移除并记录日志
            if (item.retryCount > 5) {
                logger.warn(`🚨 请求 ${item.id} (${item.type}) 成为死信 (Retry > 5)，已丢弃。Payload: ${JSON.stringify(item.payload)}`);
                await ctx.database.remove('blacklist_request_queue', {id: item.id});
                continue;
            }

            try {
                await ctx.http.post(`${config.remoteApiUrl}/applications`, {
                    ...item.payload,
                    instanceId,
                    isOfflineRetry: true
                }, {
                    headers: {Authorization: `Bearer ${config.apiToken}`},
                    timeout: 5000
                });

                await ctx.database.remove('blacklist_request_queue', {id: item.id});
                logger.info(`✅ 离线请求 ${item.id} 同步成功`);

            } catch (error: any) {
                const isNetworkError = error.code === 'ECONNABORTED' || error.code === 'ENOTFOUND' || !error.response;

                if (isNetworkError) {
                    // 网络问题：单纯保留，不增加死信计数(或者增加得慢一点)，等待网络恢复
                    logger.debug(`离线请求 ${item.id} 网络失败，等待重连。`);
                } else {
                    // 业务错误 (400/500)：增加重试计数
                    logger.warn(`离线请求 ${item.id} 业务报错: ${error.message}`);
                    await ctx.database.set('blacklist_request_queue', {id: item.id}, {
                        retryCount: item.retryCount + 1
                    });
                }
            }
        }
    } catch (err) {
        logger.error(`队列处理发生未知异常: ${err}`);
    } finally {
        isProcessingQueue = false; // 释放锁
    }
}

// --- 5. 用户检查核心 ---
export async function checkAndHandleUser(ctx: Context, config: PluginConfig, session: Session, user_id: string, isBatchScan: boolean = false): Promise<boolean> {
    const startTime = performance.now();

    // 1. 初始化标准状态机切面
    const traceData: Record<string, any> = {
        guild_id: session.guildId ? String(session.guildId) : 'unknown',
        target_user_id: String(user_id),
        guild_mode: 'unknown',
        bypass_reason: 'none',       // 放行原因
        notify_status: 'skipped',    // 通知状态: skipped | success | fail
        kick_status: 'skipped',      // 踢出状态: skipped | success | fail
        verify_status: 'skipped',    // 验证状态: skipped | success | fail
        kick_retries: 0,             // Metric: 重试次数
        is_kicked: false,            // Tag
    };

    // 定义统一的收尾闭包，确保任何出口都能精准上报
    const finalizeTrace = () => {
        if (!isBatchScan) {
            traceData.cost_ms = Math.round(performance.now() - startTime); // Metric: 总耗时
            emitTelemetry(ctx, config, 'handle_user_trace', traceData);
        }
    };

    if (!session.guildId) {
        traceData.bypass_reason = 'no_guild';
        finalizeTrace();
        return false;
    }

    const guildSettings = await ctx.database.get('blacklist_guild_settings', {guildId: session.guildId});
    const mode = guildSettings[0]?.mode || config.defaultGuildMode;
    traceData.guild_mode = mode;

    if (mode === 'off') {
        traceData.bypass_reason = 'mode_off';
        finalizeTrace();
        return false;
    }

    // --- 拦截判断层 ---
    const protectedSet = new Set(config.protectedUsers || []);
    if (protectedSet.has(user_id)) {
        traceData.bypass_reason = 'local_whitelist';
        finalizeTrace();
        return false;
    }

    const whitelistEntries = await ctx.database.get('blacklist_whitelist', {user_id});
    if (whitelistEntries.length > 0) {
        traceData.bypass_reason = 'cloud_whitelist';
        finalizeTrace();
        return false;
    }

    const entries = await ctx.database.get('blacklist_users', {user_id, disabled: false});
    if (entries.length === 0) {
        traceData.bypass_reason = 'not_in_blacklist';
        finalizeTrace();
        return false;
    }

    if (await isUserAdmin(session, config, user_id)) {
        traceData.bypass_reason = 'admin_bypass';
        finalizeTrace();
        return false;
    }

    // 进入实质性处理阶段
    const entry = entries[0];
    const reason = entry.reason || 'QQ号黑名单';
    traceData.match_reason = reason;

    let displayName = user_id;
    try {
        const member = await session.bot.getGuildMember(session.guildId, user_id);
        displayName = member.nick || member.user?.name || user_id;
    } catch {
    }

    // --- 执行通知层 ---
    if (mode === 'notify' || mode === 'both') {
        const tpl = mode === 'notify' ? config.adminNotifyMessage : config.kickNotifyMessage;
        const msg = tpl
            .replace('{user}', displayName)
            .replace('{userId}', user_id)
            .replace('{reason}', reason)
            .replace('{guild}', session.guildId);

        try {
            await session.send(session.messageId ? h('quote', {id: session.messageId}) + msg : msg);
            traceData.notify_status = 'success';
        } catch (e: any) {
            traceData.notify_status = 'fail';
            traceData.notify_error_code = e.code || e.name || 'UnknownError';
        }
    }

    // --- 执行踢出与验证层 ---
    if (mode === 'kick' || mode === 'both') {
        for (let i = 0; i < config.retryAttempts; i++) {
            traceData.kick_retries = i;
            try {
                await session.bot.kickGuildMember(session.guildId, user_id);
                traceData.is_kicked = true;
                traceData.kick_status = 'success';
                break;
            } catch (e: any) {
                if (i === config.retryAttempts - 1) {
                    traceData.kick_status = 'fail';
                    traceData.kick_error_code = e.code || e.name || 'UnknownError';
                    try {
                        await session.send(config.kickFailMessage.replace('{user}', displayName).replace('{reason}', String(e)));
                    } catch {
                    }
                } else {
                    await sleep(config.retryDelay);
                }
            }
        }

        if (traceData.is_kicked && config.verifyKickResult) {
            await sleep(2000);
            try {
                await session.bot.getGuildMember(session.guildId, user_id);
                traceData.verify_status = 'fail'; // 还能获取到，说明踢出实质性失败
            } catch {
                traceData.verify_status = 'success';
            }
        }
    }
    finalizeTrace();
    return traceData.is_kicked;
}

export function parseUserId(input: string): string {
    if (!input) return "";
    const atMatch = input.match(/<at id="([^"]+)"\/>/);
    if (atMatch) input = atMatch[1];
    if (input.includes(':')) return input.split(':')[1];
    return input;
}

// 通用的群组扫描函数
export async function scanGuild(
    ctx: Context,
    config: PluginConfig,
    bot: any, // 传入具体的 bot 实例
    guildId: string
): Promise<{ handled: number; total: number; error?: string }> {
    try {
        const scanStartTime = performance.now();
        // 1. 获取群成员
        const members = await bot.getGuildMemberList(guildId);

        // 2. 获取本地黑名单缓存
        const blacklist = await ctx.database.get('blacklist_users', {disabled: false});
        const whitelist = await ctx.database.get('blacklist_whitelist', {});

        const blacklistSet = new Set(blacklist.map(b => b.user_id));
        const whitelistSet = new Set(whitelist.map(w => w.user_id));
        const protectedSet = new Set(config.protectedUsers || []);

        // 3. 筛选目标 (内存操作，极快)
        const targets = members.data.filter((m: { user: { id: string; isBot: any; }; }) => {
            const uid = m.user?.id;
            if (!uid) return false;
            if (config.skipBotMembers && m.user.isBot) return false;

            // 白名单过滤
            if (protectedSet.has(uid)) return false;
            if (whitelistSet.has(uid)) return false;

            return blacklistSet.has(uid);
        });

        if (targets.length === 0) return {handled: 0, total: 0};

        // 4. 构造伪造的 Session 用于复用 checkAndHandleUser 逻辑
        // 注意：checkAndHandleUser 内部依赖 session.send 发送通知
        // 全局扫描时可能不需要每踢一个人都发消息，或者需要构造一个静默的 session
        const fakeSession = bot.session({
            type: 'message',
            guildId,
            channelId: guildId,
            user: {id: bot.selfId},
        });

        let handled = 0;
        const handledUserIds: string[] = []; // 用于收集明细
        const BATCH_SIZE = 5;

        // 5. 分批执行
        for (let i = 0; i < targets.length; i += BATCH_SIZE) {
            const batch = targets.slice(i, i + BATCH_SIZE);
            await Promise.all(batch.map(async (m: any) => {
                if (m.user?.id) {
                    const isKicked = await checkAndHandleUser(ctx, config, fakeSession, m.user.id, true);
                    if (isKicked) {
                        handled++;
                        handledUserIds.push(m.user.id);
                    }
                }
            }));
        }

        const costMs = Math.round(performance.now() - scanStartTime);

        emitTelemetry(ctx, config, 'scan_guild_summary', {
            guild_id: String(guildId),
            bot_id: String(bot.selfId),
            members_total: members.data.length, // Metric
            targets_found: targets.length,      // Metric
            handled_count: handled,             // Metric
            scan_cost_ms: costMs,               // Metric
            status: 'success'
        });

        if (handled > 0) {
            pushToSampleQueue(ctx, config, 'scan_kick_records', guildId, {
                scan_time: Date.now(),
                bot_id: bot.selfId,
                kicked_users: handledUserIds
            });
        }

        return {handled, total: targets.length};
    } catch (error: any) {
        emitTelemetry(ctx, config, 'scan_guild_summary', {
            guild_id: String(guildId),
            bot_id: String(bot.selfId),
            status: 'error',
            error_code: error.code || error.name || 'ScanError'
        });

        return {handled: 0, total: 0, error: String(error)};
    }
}

export async function scanAllGuilds(ctx: Context, config: PluginConfig) {
    let totalHandled = 0;
    let processedGuilds = 0;

    for (const bot of ctx.bots) {
        try {
            const guilds = await bot.getGuildList();
            for (const guild of guilds.data) {
                // 调用现有的单群扫描逻辑
                const result = await scanGuild(ctx, config, bot, guild.id);
                if (result.handled > 0) {
                    logger.info(`[自动扫描] 群 ${guild.id}: 处理 ${result.handled} 人`);
                    totalHandled += result.handled;
                }
                processedGuilds++;
            }
        } catch (e) {
            logger.warn(`Bot ${bot.selfId} 自动扫描出错: ${e}`);
        }
    }
    logger.info(`✅ 扫描完成。扫描群组: ${processedGuilds}, 处理人数: ${totalHandled}`);
}

function buildTelemetryEndpoint(baseUrl: string, path: string): string {
    if (!baseUrl) return '';
    const cleanBase = baseUrl.replace(/\/+$/, '');
    return `${cleanBase}${path}`;
}

export function emitTelemetry(ctx: Context, config: PluginConfig, type: string, payload: Record<string, any>) {
    if (!config.enableTelemetry || !config.telemetryApiUrl) return;

    // 1. 构建扁平化的基础结构
    const safePayload: Record<string, any> = {
        app: 'blacklist_online',
        type: type,
        timestamp: Date.now()
    };

    // 2. 严格的类型清洗 (洗盘逻辑)
    for (const [key, value] of Object.entries(payload)) {
        if (value === null || value === undefined) continue;

        const lowerKey = key.toLowerCase();

        // 强制防呆：任何以 id 结尾的字段，或明确的 user/guild 标识，必须强转为 String，防止被当做 Metrics
        if (lowerKey.endsWith('id') || lowerKey === 'qq') {
            safePayload[key] = String(value);
        }
        // 防止深层嵌套引发后端解析回退
        else if (typeof value === 'object') {
            safePayload[key] = JSON.stringify(value);
        } else {
            safePayload[key] = value; // Number 留作 Metrics，Boolean/String 留作 Tags
        }
    }

    // 3. 旁路异步发送 (Fire-and-Forget)，屏蔽报错以防污染主日志
    const targetUrl = buildTelemetryEndpoint(config.telemetryApiUrl, '/api/push');
    ctx.http.post(targetUrl, safePayload, {timeout: 3000}).catch(err => {
        logger.debug(`[Telemetry] 上报异常 (${type}): ${err.message}`);
    });
}

export function pushToSampleQueue(ctx: Context, config: PluginConfig, topic: string, groupKey: string, sampleData: any) {
    if (!config.enableTelemetry || !config.telemetryApiUrl) return;

    const payload = {
        topic: topic,
        group_key: String(groupKey),
        sample_data: sampleData,
        max_samples: 10 // 仅保留最近的 10 次扫描明细即可
    };

    const targetUrl = buildTelemetryEndpoint(config.telemetryApiUrl, '/api/sys/queue/push');
    ctx.http.post(targetUrl, payload, {timeout: 3000}).catch(err => {
        logger.debug(`[Telemetry-Queue] 队列投递异常 (${topic}): ${err.message}`);
    });
}