import type { Rate } from './rate'

export type UsersResponse = {
  items: User[]
  total: number
}

export type User = {
  id: string
  fingerprint: string
  uid: string | null
  is_active: boolean
  created_at: string
  rate: Rate | null
  static_ip: string | null
  group_id: string | null
  email: string | null
  has_password: boolean
  telegram_id: number | null
  balance: number
  activated_at: string | null
  expires_at: string | null
}

export type UpdateUserRequest = {
  uid?: string
  is_active?: boolean
  static_ip?: string | null
  group_id?: string | null
  clear_group?: boolean
  email?: string | null
  clear_email?: boolean
  password?: string
  clear_password?: boolean
}

export type RegenerateUserRequest = {
  id: string
  uid: string | null
  fingerprint: string
  private_key: string
  public_key: string
}

export type CreateUserRequest = {
  uid: string
  group_id: string | null
  email?: string | null
  password?: string | null
}

export type AddUserResponse = {
  id: string
  uid: string
  fingerprint: string
  private_key: string
  public_key: string
  rate: Rate | null
}
