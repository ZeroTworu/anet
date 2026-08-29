import { api } from './client'
import type { UserGroup, SaveGroupRequest } from '@/models/group'
import type { UsersResponse } from '@/models/user'
import { toQuery } from '@/utils'

export const GetGroups = () => api<UserGroup[]>('/groups')

export const GetGroup = (id: string) => api<UserGroup>(`/groups/${id}`)

export const CreateGroup = (group: SaveGroupRequest) => api<UserGroup>('/groups', {
    method: 'POST',
    data: group,
})

export const UpdateGroup = (id: string, group: SaveGroupRequest) => api<UserGroup>(`/groups/${id}`, {
    method: 'PATCH',
    data: group,
})

export const DeleteGroup = (id: string) => api<void>(`/groups/${id}`, {
    method: 'DELETE',
})

// Новые эндпоинты Lazy Load управления участниками группы:

export const GetGroupMembers = (id: string, from = 0, limit = 10, search?: string) =>
    api<UsersResponse>(`/groups/${id}/members?${toQuery({ from, limit, search })}`)

export const AddGroupMember = (id: string, userId: string) =>
    api<void>(`/groups/${id}/members`, {
        method: 'POST',
        data: { user_id: userId },
    })

export const RemoveGroupMember = (id: string, userId: string) =>
    api<void>(`/groups/${id}/members/${userId}`, {
        method: 'DELETE',
    })
