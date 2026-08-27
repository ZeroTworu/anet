import { api } from './client'
import type { NodePool, SaveNodePoolRequest } from '@/models/pool'

export const GetPools = () => api<NodePool[]>('/pools')
export const CreatePool = (pool: SaveNodePoolRequest) => api<NodePool>('/pools', {
  method: 'POST', data: pool,
})
export const UpdatePool = (id: string, pool: SaveNodePoolRequest) => api<NodePool>(`/pools/${id}`, {
  method: 'PATCH', data: pool,
})
export const DeletePool = (id: string) => api<void>(`/pools/${id}`, { method: 'DELETE' })
