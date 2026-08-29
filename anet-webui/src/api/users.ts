import {
  type User,
  type UsersResponse,
  type UpdateUserRequest,
  type RegenerateUserRequest,
  type CreateUserRequest,
} from '@/models/user'
import { api } from './client'
import { toQuery } from '@/utils'

export async function GetUsers(
    from: number = 0,
    limit: number = 10,
    search?: string,
    groupIds?: string[],
    sortBy?: string,       // <-- Новое
    descending?: boolean,  // <-- Новое
): Promise<UsersResponse> {
  const params = toQuery({
    from: from,
    limit: limit,
    search: search || undefined,
    group_ids: groupIds && groupIds.length ? groupIds.join(',') : undefined,
    sort_by: sortBy || undefined,
    descending: descending !== undefined ? String(descending) : undefined,
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
    data,
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
    data,
  })
}
