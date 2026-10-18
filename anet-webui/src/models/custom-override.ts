export type OverrideType = 'domain' | 'wildcard' | 'cidr'
export type OverrideCategory = 'block' | 'direct' | 'proxy'

export interface CustomOverride {
  id: string
  route_map_id: string | null
  rule_type: OverrideType
  pattern: string
  category: OverrideCategory
  comment: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface SaveCustomOverrideRequest {
  route_map_id: string | null
  rule_type: OverrideType
  pattern: string
  category: OverrideCategory
  comment: string
  is_active: boolean
}
