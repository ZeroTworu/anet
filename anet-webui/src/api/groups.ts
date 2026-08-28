import { api } from './client'
import type { UserGroup, SaveGroupRequest } from '@/models/group'

export const GetGroups = () => api<UserGroup[]>('/groups')

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
