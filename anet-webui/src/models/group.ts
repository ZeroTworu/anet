export type UserGroup = {
    id: string
    name: string
    traffic_limit: number     // в байтах (0 - безлимит)
    speed_limit: number       // в kbps (0 - безлимит)
    sessions_limit: number    // кол-во одновременных сессий
    duration_days: number     // дельта дней
    created_at: string
    updated_at: string
    user_ids: string[]
}

export type SaveGroupRequest = Omit<UserGroup, 'id' | 'created_at' | 'updated_at'>
