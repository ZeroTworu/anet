import { api } from './client'
import type { RouteMap, SaveRouteMapRequest } from '@/models/route-map'

// Route map хранится на панели и компилируется при выдаче client.toml.

export const GetRouteMaps = () => api<RouteMap[]>('/route-maps')
export const CreateRouteMap = (routeMap: SaveRouteMapRequest) => api<RouteMap>('/route-maps', {
  method: 'POST', data: routeMap,
})
export const UpdateRouteMap = (id: string, routeMap: SaveRouteMapRequest) => api<RouteMap>(`/route-maps/${id}`, {
  method: 'PATCH', data: routeMap,
})
export const DeleteRouteMap = (id: string) => api<void>(`/route-maps/${id}`, { method: 'DELETE' })
