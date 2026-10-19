// Декларативная политика split tunneling пользователя.
export type RouteRuleMatchType = 'cidr' | 'application' | 'domain' | 'rule_provider'
export type RouteRuleAction = 'tunnel' | 'direct' | 'block' | 'proxy'

export type RouteRule = {
  id?: string | null
  position: number
  match_type: RouteRuleMatchType
  match_value: string
  action: RouteRuleAction
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