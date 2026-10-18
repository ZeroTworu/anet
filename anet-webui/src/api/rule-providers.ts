import { api } from './client'
import type { RuleProvider, SaveRuleProviderRequest } from '@/models/rule-provider'

export const GetRuleProviders = () => api<RuleProvider[]>('/routing/rule-providers')

export const CreateRuleProvider = (data: SaveRuleProviderRequest) =>
  api<RuleProvider>('/routing/rule-providers', {
    method: 'POST',
    data,
  })

export const UpdateRuleProvider = (id: string, data: SaveRuleProviderRequest) =>
  api<RuleProvider>(`/routing/rule-providers/${id}`, {
    method: 'PUT',
    data,
  })

export const DeleteRuleProvider = (id: string) =>
  api<void>(`/routing/rule-providers/${id}`, { method: 'DELETE' })

export const FetchRuleProviderNow = (id: string) =>
  api<RuleProvider>(`/routing/rule-providers/${id}/fetch`, {
    method: 'POST',
  })
