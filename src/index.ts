import {Context, Schema, Time} from 'koishi';
import { randomUUID } from 'node:crypto'; // 【修复】使用原生 crypto
import {
  isUserAdmin, syncBlacklist, queueRequest, processOfflineQueue, checkAndHandleUser, scanGuild, sleep,
  parseUserId
} from './core';
import { PluginConfig, GuildSettings } from './types';

export const name = 'blacklist-online';
export const inject = ['database', 'http'];

export const usage = `
## 功能说明
一个强大的、基于数据库的群组黑名单管理插件。
- **受保护名单**: 配置中的用户无法被拉黑。
- **分群管理**: 可为每个群独立设置黑名单处理模式。
- **入群扫描**: 可配置机器人在加入新群组时，自动扫描群内现有成员。
- **自动拒绝**: 自动拒绝数据库黑名单用户的加群申请。
- **手动扫描**: 提供指令手动扫描当前或全部群组。
- **权限控制**: 所有指令均有权限等级控制。
`;

// --- Schema 定义 ---
export const Config: Schema<PluginConfig> = Schema.intersect([
  Schema.object({
    remoteApiUrl: Schema.string().required().description('远程黑名单中心 API 地址 (建议 HTTPS)'),
    apiToken: Schema.string().role('secret').required().description('API 访问令牌'),
    adminRoles: Schema.array(String).default(['owner', 'admin']).description('管理员角色名 (不区分大小写)'),
    protectedUsers: Schema.array(String).role('table').description('本地受保护用户 (白名单)'),
    defaultGuildMode: Schema.union([
      Schema.const('off').description('关闭'),
      Schema.const('notify').description('仅通知'),
      Schema.const('kick').description('仅踢出'),
      Schema.const('both').description('通知并踢出'),
    ]).default('off').description('新群组默认模式'),
  }).description('核心设置'),

  Schema.object({
    enableAutoReject: Schema.boolean().default(true).description("自动拒绝加群申请"),
    skipBotMembers: Schema.boolean().default(true).description("跳过其他机器人"),
    retryAttempts: Schema.number().default(3).description("踢人重试次数"),
    retryDelay: Schema.number().default(2000).description("重试间隔(ms)"),
    verifyKickResult: Schema.boolean().default(true).description("验证踢出结果"),
  }).description('高级行为'),

  Schema.object({
    rejectionMessage: Schema.string().default('您的账号存在安全风险。').description("拒绝申请理由"),
    adminNotifyMessage: Schema.string().role('textarea').default('检测到黑名单用户 {user} ({userId})。\n原因: {reason}').description('通知模式模板'),
    kickNotifyMessage: Schema.string().role('textarea').default('正在移除黑名单用户 {user} ({userId})...\n原因: {reason}').description('踢出模式模板'),
    kickFailMessage: Schema.string().role('textarea').default('⚠️ 无法踢出用户 {user}。\n错误: {reason}').description('失败通知'),
    autoRejectNotifyMessage: Schema.string().role('textarea').default('🚫 已自动拒绝黑名单用户 {user} ({userId})。').description('自动拒绝通知'),
  }).description('消息模板'),
]) as Schema<PluginConfig>;

export function apply(ctx: Context, config: PluginConfig) {
  const logger = ctx.logger('blacklist-online');

  // 1. 扩展数据库
  ctx.model.extend('blacklist_users', {
    user_id: 'string',
    reason: 'string',
    disabled: { type: 'boolean', initial: false },
    operator_id: 'string',
    source_id: 'string',
    updated_at: 'timestamp'
  }, { primary: 'user_id' });
  ctx.model.extend('blacklist_request_queue', {
    id: 'string', type: 'string', payload: 'json', createdAt: 'timestamp', retryCount: 'unsigned'
  }, {primary: 'id'});
  ctx.model.extend('blacklist_meta', {
    key: 'string', value: 'string'
  }, {primary: 'key'});
  ctx.model.extend('blacklist_guild_settings', {
    guildId: 'string', mode: 'string'
  }, {primary: 'guildId'});

  // 2. 初始化
  ctx.on('ready', async () => {
    // 生成/读取 InstanceUUID
    const entries = await ctx.database.get('blacklist_meta', {key: 'instance_uuid'});
    if (entries.length === 0) {
      const uuid = randomUUID();
      await ctx.database.create('blacklist_meta', {key: 'instance_uuid', value: uuid});
      logger.info(`✨ 初始化实例 UUID: ${uuid}`);
    } else {
      logger.info(`📱 当前实例 UUID: ${entries[0].value}`);
    }

    // 启动时立即同步一次
    syncBlacklist(ctx, config);
    // 启动时处理积压队列
    processOfflineQueue(ctx, config);
  });

  // 3. 定时任务
  ctx.setInterval(() => syncBlacklist(ctx, config), 5 * Time.minute); // 每5分同步
  ctx.setInterval(() => processOfflineQueue(ctx, config), Time.minute); // 每1分处理队列

  // 4. 事件监听

  // 监听加群申请 (自动拒绝)
  ctx.on('guild-member-request', async (session) => {
    if (!config.enableAutoReject || !session.userId) return;

    // 先查本地白名单
    if (config.protectedUsers.includes(session.userId)) return;

    // 查库
    const entries = await ctx.database.get('blacklist_users', {user_id: session.userId, disabled: false});
    if (entries.length > 0) {
      try {
        await session.bot.handleGuildRequest(session.messageId!, false, config.rejectionMessage);
        logger.info(`🚫 自动拒绝: ${session.userId}`);
        const msg = config.autoRejectNotifyMessage.replace('{user}', session.userId).replace('{userId}', session.userId);
        await session.send(msg);
      } catch (e) {
        logger.warn(`拒绝申请失败: ${e}`);
      }
    }
  });

  // 监听新成员加入
  ctx.on('guild-member-added', async (session) => {
    if (!session.userId || !session.guildId) return;
    if (config.skipBotMembers && session.author?.isBot) return;

    await checkAndHandleUser(ctx, config, session, session.userId);
  });

  // 5. 指令集
  const cmd = ctx.command('blacklist', '黑名单管理');

  // 子指令: 申请拉黑
  cmd.subcommand('.request <user:string> <reason:text>', '申请拉黑', {authority: 2})
    .action(async ({session}, user, reason) => {
      if (!session?.guildId) return '请在群组中使用。';
      if (!reason) return '请填写理由。';

      const userId = parseUserId(user)
      // 本地白名单前置拦截
      if (config.protectedUsers.includes(userId)) return '❌ 该用户在本地白名单中，无法拉黑。';

      const requestId = randomUUID();
      const payload = {
        request_id: requestId,
        type: 'ADD',
        applicant_id: session.userId,
        target_user_id: userId,
        reason,
        guild_id: session.guildId,
        timestamp: Date.now()
      };

      try {
        await ctx.http.post(`${config.remoteApiUrl}/applications`, payload, {
          headers: {Authorization: `Bearer ${config.apiToken}`}
        });
        return `✅ 申请已提交至云端，请等待审批。\n🆔 申请ID: ${requestId}\n(可使用 blacklist.cancel 指令撤回)`;
      } catch (e) {
        // 失败入队
        await queueRequest(ctx, 'ADD', payload);
        return `⚠️ 无法连接服务器，申请已加入离线队列。\n🆔 申请ID: ${requestId}\n将在网络恢复后自动提交。(可使用 blacklist.cancel 指令撤回)`;
      }
    });

  // 子指令: 申请删除
  cmd.subcommand('.delete <user:string> <reason:text>', '申请移除', {authority: 2})
    .action(async ({session}, user, reason) => {
      if (!session) return '无有效session。';
      if (!reason) return '请填写理由。';
      const userId = parseUserId(user)

      const requestId = randomUUID();
      const payload = {
        request_id: requestId,
        type: 'REMOVE',
        applicant_id: session.userId,
        target_user_id: userId,
        reason,
        timestamp: Date.now()
      };

      try {
        await ctx.http.post(`${config.remoteApiUrl}/applications`, payload, {
          headers: {Authorization: `Bearer ${config.apiToken}`}
        });
        return `✅ 移除申请已提交。\n🆔 申请ID: ${requestId}`;
      } catch (e) {
        await queueRequest(ctx, 'REMOVE', payload);
        return `⚠️ 网络故障，移除申请已加入离线队列。\n🆔 申请ID: ${requestId}`;
      }
    });

  // 子指令: 撤回申请
  cmd.subcommand('.cancel <uuid:string>', '撤回申请', {authority: 2})
    .action(async ({session}, uuid) => {
      if (!uuid) return '请输入要撤回的申请 UUID。';

      const payload = {
        request_id: randomUUID(),
        target_request_id: uuid,
        applicant_id: session?.userId,
        timestamp: Date.now()
      };

      try {
        await ctx.http.post(`${config.remoteApiUrl}/applications/cancel`, payload, {
          headers: {Authorization: `Bearer ${config.apiToken}`}
        });
        return `✅ 针对申请 ${uuid} 的撤回指令已发送。`;
      } catch (e) {
        await queueRequest(ctx, 'CANCEL', payload);
        return `⚠️ 网络故障，针对 ${uuid} 的撤回指令已加入离线队列。`;
      }
    });

  // 子指令: 设置模式
  cmd.subcommand('.mode <mode:string>', '设置当前群处理模式', {authority: 3})
    .action(async ({session}, mode) => {
      if (!session?.guildId) return;
      const valid = ['off', 'notify', 'kick', 'both'];
      if (!valid.includes(mode)) return `无效模式。可用: ${valid.join(', ')}`;

      await ctx.database.upsert('blacklist_guild_settings', [{
        guildId: session.guildId,
        mode: mode as GuildSettings['mode']
      }]);
      return `当前群模式已设置为: ${mode}`;
    });

  const scanCmd = cmd.subcommand('.scan', '黑名单扫描', {authority: 3});

  // 扫描当前群
  scanCmd.action(async ({session}) => {
    if (!session?.guildId) return '请在群组中使用。';

    session.send('🔍 开始扫描本群...');
    const result = await scanGuild(ctx, config, session.bot, session.guildId);

    if (result.error) return `⚠️ 扫描出错: ${result.error}`;
    return `✅ 扫描结束。发现目标 ${result.total} 人，成功处理 ${result.handled} 人。`;
  });

  // 扫描所有群
  scanCmd.subcommand('.all', '扫描所有群组 (高负载)', {authority: 4})
    .action(async ({session}) => {
      session?.send('🚀 开始全局扫描，这可能需要一些时间...');
      const logger = ctx.logger('blacklist-online');

      let totalGuilds = 0;
      let totalHandled = 0;
      let processedGuilds = 0;

      // 遍历所有机器人实例
      for (const bot of ctx.bots) {
        try {
          const guilds = await bot.getGuildList();
          totalGuilds += guilds.data.length;

          for (const guild of guilds.data) {
            // 逐个群扫描
            const result = await scanGuild(ctx, config, bot, guild.id);
            if (result.handled > 0) {
              logger.info(`[全局扫描] 群 ${guild.id}: 处理 ${result.handled}/${result.total}`);
              totalHandled += result.handled;
            }
            processedGuilds++;
          }
        } catch (e) {
          logger.warn(`Bot ${bot.selfId} 获取群列表失败: ${e}`);
        }
      }

      return `✅ 全局扫描完成！\n共扫描群组: ${processedGuilds}/${totalGuilds}\n共处理黑名单用户: ${totalHandled} 人`;
    });
}
