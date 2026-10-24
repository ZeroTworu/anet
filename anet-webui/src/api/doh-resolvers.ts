import { api } from './client'
import type { DohResolver, SaveDohResolverRequest } from '@/models/doh-resolver'

export const GetDohResolvers = () =>
  api<DohResolver[]>('/doh-resolvers')

export const CreateDohResolver = (data: SaveDohResolverRequest) =>
  api<DohResolver>('/doh-resolvers', {
    method: 'POST',
    data,
  })

export const UpdateDohResolver = (id: string, data: SaveDohResolverRequest) =>
  api<DohResolver>(`/doh-resolvers/${id}`, {
    method: 'PUT',
    data,
  })

export const DeleteDohResolver = (id: string) =>
  api<void>(`/doh-resolvers/${id}`, { method: 'DELETE' })
