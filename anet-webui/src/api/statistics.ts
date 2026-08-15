import { api } from './client'
import type { NodeTrafficStat, TrafficHistoryPoint, UserTrafficStat } from '@/models/statistics'

// Эти данные строятся из cumulative отчётов нод и не требуют входящего API.

export const GetNodeTrafficStats = () => api<NodeTrafficStat[]>('/statistics/nodes')

export const GetUserTrafficStats = () => api<UserTrafficStat[]>('/statistics/users')

export const GetTrafficHistory = (hours = 24) =>
  api<TrafficHistoryPoint[]>(`/statistics/traffic/history?hours=${hours}`)
