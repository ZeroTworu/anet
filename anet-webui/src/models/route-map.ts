// Декларативная политика split tunneling пользователя.
export type RouteRule = {
  id?: string | null
  position: number
  match_type: 'cidr' | 'application'
  match_value: string
  action: 'tunnel' | 'direct'
}

export type RouteMap = {
  id: string
  name: string
  description: string
  default_action: 'tunnel' | 'direct'
  is_active: boolean
  revision: number
  rules: RouteRule[]
  rules_count?: number
}

export type SaveRouteMapRequest = Omit<RouteMap, 'id' | 'revision' | 'rules_count'>