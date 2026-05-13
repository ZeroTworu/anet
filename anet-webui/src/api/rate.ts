import type { Rate, RateReqRequest } from '@/models/rate'
import { api } from './client'
import { toQuery } from '@/utils'

export async function UpdateRate(id: string, data: RateReqRequest): Promise<Rate> {
  console.log(data.date_end)
  return api<Rate>(`/rate/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  })
}

export async function AddRate(user_id: string, data: RateReqRequest): Promise<Rate> {
  const params = toQuery({
    user_id: user_id,
  })
  return api<Rate>(`/addrate?${params}`, {
    method: 'POST',
    body: JSON.stringify(data),
  })
}
