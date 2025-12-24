// 插件配置的完整类型定义
export interface PluginConfig {
  // --- 远程连接 ---
  remoteApiUrl: string;
  apiToken: string;

  // --- 权限与策略 ---
  adminRoles: string[]; // 自定义管理员角色
  protectedUsers: string[]; // 本地白名单
  defaultGuildMode: 'off' | 'notify' | 'kick' | 'both';

  // --- 行为开关 ---
  enableAutoReject: boolean;
  skipBotMembers: boolean;
  retryAttempts: number;
  retryDelay: number;
  verifyKickResult: boolean;

  // --- 消息模板 ---
  rejectionMessage: string;
  adminNotifyMessage: string;
  kickNotifyMessage: string;
  kickFailMessage: string;
  autoRejectNotifyMessage: string;
}

// 数据库：黑名单用户 (本地缓存)
export interface BlacklistEntry {
  user_id: string;
  reason: string;
  operator_id?: string;
  source_id?: string;
  disabled: boolean;
  updated_at: Date;
}

// 数据库：云端白名单用户 (本地缓存)
export interface WhitelistEntry {
  user_id: string;
  reason?: string;
  operator_id?: string;
  created_at: Date;
}

// 数据库：离线请求队列
export interface OfflineRequest {
  id: string;          // 请求 UUID
  type: 'ADD' | 'REMOVE' | 'CANCEL';
  payload: any;        // 请求体
  createdAt: Date;
  retryCount: number;
}

// 数据库：元数据 (InstanceUUID, SyncRevision)
export interface MetaEntry {
  key: string;
  value: string;
}

// 数据库：群组设置
export interface GuildSettings {
  guildId: string;
  mode: 'off' | 'notify' | 'kick' | 'both';
}

// 扩展 Koishi 表结构
declare module 'koishi' {
  interface Tables {
    blacklist_users: BlacklistEntry;
    blacklist_whitelist: WhitelistEntry;
    blacklist_request_queue: OfflineRequest;
    blacklist_meta: MetaEntry;
    blacklist_guild_settings: GuildSettings;
  }
}
