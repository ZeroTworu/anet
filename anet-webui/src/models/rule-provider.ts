export type ProviderType = 'domain' | 'ip'
export type ProviderFormat = 'plain' | 'v2ray' | 'cidr'

export interface RuleProvider {
  id: string
  name: string
  description: string
  provider_type: ProviderType
  format: ProviderFormat
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
  url: string
  update_interval_hours: number
  is_active: boolean
}
