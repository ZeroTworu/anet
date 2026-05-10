import type { Rate, RateReqRequest } from './rate'

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
}

export type UpdateUserRequest = {
  uid: string
  is_active: boolean
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
  rate: RateReqRequest | null
}
