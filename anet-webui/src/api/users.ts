import {api} from './client'

type UsersRequest = {
    from: number
    limit: number
}

export type UsersResponse = {
    items: Item[]
    total: number
}

type Item = {
    created_at: string
    fingerprint: string
    id: string
    is_active: boolean
    rate: number | null
    static_ip: string | null
    uid: string
}

export async function getUsers(from: number = 0, limit: number = 10): Promise<UsersResponse> {
    const params = toQuery({
        from: from,
        limit: limit,
    })

    const res = await api<UsersResponse>(`/users?${params}`)

    return res
}

function toQuery(params: Record<string, string | number | null | undefined>) {
  const search = new URLSearchParams()

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      search.append(key, String(value))
    }
  })

  return search.toString()
}