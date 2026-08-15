import { api } from './client'
import type { NodePool, SaveNodePoolRequest } from '@/models/pool'

// CRUD pools: resolver панели сам исключает offline и admission-closed ноды.

export const GetPools = () => api<NodePool[]>('/pools')
export const CreatePool = (pool: SaveNodePoolRequest) => api<NodePool>('/pools', {
  method: 'POST', body: JSON.stringify(pool),
})
export const UpdatePool = (id: string, pool: SaveNodePoolRequest) => api<NodePool>(`/pools/${id}`, {
  method: 'PATCH', body: JSON.stringify(pool),
})
export const DeletePool = (id: string) => api<void>(`/pools/${id}`, { method: 'DELETE' })
