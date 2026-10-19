export type ProviderType = 'domain' | 'ip'
export type ProviderFormat = 'plain' | 'v2ray' | 'cidr'
export type ProviderAction = 'block' | 'direct' | 'proxy'

export interface RuleProvider {
  id: string
  name: string
  description: string
  provider_type: ProviderType
  format: ProviderFormat
  action: ProviderAction
  route_map_id: string | null
  url: string
  update_interval_hours: number
  last_fetched_at: string | null
  last_etag: string | null
  item_count: number
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface SaveRuleProviderRequest {
  name: string
  description: string
  provider_type: ProviderType
  format: ProviderFormat
  action: ProviderAction
  route_map_id: string | null
  url: string
  update_interval_hours: number
  is_active: boolean
}

export interface ProviderItem {
  id: number
  rule_value: string
}

export interface RuleProviderItemsPage {
  provider_id: string
  provider_name: string
  total: number
  page: number
  per_page: number
  items: ProviderItem[]
}
