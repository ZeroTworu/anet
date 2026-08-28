import { api } from './client'
import type { NodeTrafficStat, TrafficHistoryPoint, UserTrafficStat, ActiveConnection } from '@/models/statistics'

export const GetNodeTrafficStats = () => api<NodeTrafficStat[]>('/statistics/nodes')

export const GetUserTrafficStats = () => api<UserTrafficStat[]>('/statistics/users')

export const GetActiveConnections = () => api<ActiveConnection[]>('/statistics/active-connections')

export const GetTrafficHistory = (
    hours = 24,
    serverId?: string,
    userId?: string,
    fingerprint?: string,
    protocol?: string
) => {
    let url = `/statistics/traffic/history?hours=${hours}`
    if (serverId) url += `&server_id=${serverId}`
    if (userId) url += `&user_id=${userId}`
    if (fingerprint) url += `&fingerprint=${fingerprint}`
    if (protocol) url += `&protocol=${protocol}`
    return api<TrafficHistoryPoint[]>(url)
}
