import {
  type User,
  type UsersResponse,
  type UpdateUserRequest,
  type RegenerateUserRequest,
  type CreateUserRequest,
  type AddUserResponse,
} from '@/models/user'
import { api } from './client'
import { toQuery } from '@/utils'

export async function GetUsers(
  from: number = 0,
  limit: number = 10,
  search?: string,
  groupIds?: string[],
  sortBy?: string,
  descending?: boolean,
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

export async function UpdateUser(id: string, data: UpdateUserRequest): Promise<User> {
  return api<User>(`/user/${id}`, {
    method: 'PATCH',
    data,
  })
}

export async function Regenerate(id: string): Promise<RegenerateUserRequest> {
  return api<RegenerateUserRequest>(`/regenerate/${id}`, {
    method: 'POST',
  })
}

export async function CreateUser(data: CreateUserRequest): Promise<AddUserResponse> {
  return api<AddUserResponse>(`/add`, {
    method: 'POST',
    data,
  })
}
