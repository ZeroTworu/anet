// Состояние, которое нода сообщает панели через исходящий heartbeat.
export type Server = {
    id: string
    name: string
    dsn: string
    public_key: string
    ssh_user: string | null
    is_active: boolean
    has_control_credential: boolean
    runtime: NodeRuntime | null
    quic_port: number | null
    ssh_port: number | null
    vnc_port: number | null
    websocket_url: string | null
}

export type NodeRuntime = {
    status: 'online' | 'offline'
    last_seen_at: string
    version: string
    uptime_seconds: number
    active_connections: number
    accepting_connections: boolean
}

export type NodeCommand = {
    command_id: string
    command_type: string
    accepting_connections: boolean | null
}

export type NodeCommandStatus = {
    command_id: string
    server_id: string
    command_type: string
    status: 'pending' | 'running' | 'succeeded' | 'failed'
    accepting_connections: boolean | null
    created_at: string
    started_at: string | null
    completed_at: string | null
    error: string | null
}

export type NodeCredential = {
    node_id: string
    token: string
}

export type CreateServerRequest = {
    name: string
    dsn: string
    public_key: string
    ssh_user: string | null
    is_active?: boolean
    quic_port?: number | null
    ssh_port?: number | null
    vnc_port?: number | null
    websocket_url?: string | null
}
