export interface DohResolver {
  id: string
  name: string
  url: string
  is_default: boolean
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface SaveDohResolverRequest {
  name: string
  url: string
  is_default: boolean
  is_active: boolean
}
