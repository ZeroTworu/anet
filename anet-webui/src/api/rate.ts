import type { Rate, RateReqRequest } from '@/models/rate'
import { api } from './client'
import { toQuery } from '@/utils'

export async function UpdateRate(id: string, data: RateReqRequest): Promise<Rate> {
  return api<Rate>(`/rate/${id}`, {
    method: 'PATCH',
    data,
  })
}

export async function AddRate(user_id: string, data: RateReqRequest): Promise<Rate> {
  const params = toQuery({
    user_id: user_id,
  })
  return api<Rate>(`/addrate?${params}`, {
    method: 'POST',
    data,
  })
}
