import { api } from './client'
import type { CustomOverride, SaveCustomOverrideRequest } from '@/models/custom-override'

export const GetCustomOverrides = (routeMapId?: string) => {
  const query = routeMapId ? `?route_map_id=${routeMapId}` : ''
  return api<CustomOverride[]>(`/routing/custom-overrides${query}`)
}

export const CreateCustomOverride = (data: SaveCustomOverrideRequest) =>
  api<CustomOverride>('/routing/custom-overrides', {
    method: 'POST',
    data,
  })

export const UpdateCustomOverride = (id: string, data: SaveCustomOverrideRequest) =>
  api<CustomOverride>(`/routing/custom-overrides/${id}`, {
    method: 'PUT',
    data,
  })

export const DeleteCustomOverride = (id: string) =>
  api<void>(`/routing/custom-overrides/${id}`, { method: 'DELETE' })
