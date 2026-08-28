import type { Rate } from './rate'

export type UsersResponse = {
  items: User[]
  total: number
}

export type User = {
  id: string
  fingerprint: string
  uid: string
  is_active: boolean
  created_at: string
  rate: Rate | null
  static_ip: string | null
  server_ids: string[]
  pool_ids: string[]
  route_map_id: string | null
  group_id: string | null
}

export type UpdateUserRequest = {
  uid: string
  is_active: boolean
  static_ip: string | null
  server_ids: string[]
  pool_ids: string[]
  route_map_id?: string
  clear_route_map?: boolean
  group_id?: string
  clear_group?: boolean
}

export type RegenerateUserRequest = {
  id: string
  uid: string
  fingerprint: string
  private_key: string
  public_key: string
}

export type CreateUserRequest = {
  uid: string
  server_ids: string[]
  pool_ids: string[]
  route_map_id: string | null
  group_id: string | null
}
