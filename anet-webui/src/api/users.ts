import {
  type User,
  type UsersResponse,
  type UpdateUserRequest,
  type RegenerateUserRequest,
  type CreateUserRequest,
} from '@/models/user'
import { api } from './client'
import { toQuery } from '@/utils'

export async function GetUsers(from: number = 0, limit: number = 10): Promise<UsersResponse> {
  const params = toQuery({
    from: from,
    limit: limit,
  })

  const res = await api<UsersResponse>(`/users?${params}`, {
    method: 'GET',
  })

  return res
}

export async function GetUser(id: string): Promise<User> {
  const res = await api<User>(`/user/${id}`, {
    method: 'GET',
  })
  return res
}

export async function UpdateUser(id: string, data: UpdateUserRequest) {
  return api<RegenerateUserRequest>(`/user/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  })
}

export async function Regenerate(id: string): Promise<RegenerateUserRequest> {
  return api<RegenerateUserRequest>(`/regenerate/${id}`, {
    method: 'POST',
  })
}

export async function CreateUser(data: CreateUserRequest): Promise<User> {
  return api<User>(`/add`, {
    method: 'POST',
    body: JSON.stringify(data),
  })
}
