export type UserGroup = {
    id: string
    name: string
    traffic_limit: number
    speed_limit: number
    sessions_limit: number
    duration_days: number
    created_at: string
    updated_at: string
    user_count: number
}

export type SaveGroupRequest = Omit<UserGroup, 'id' | 'created_at' | 'updated_at' | 'user_count'>
