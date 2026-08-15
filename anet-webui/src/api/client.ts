// src/api/client.ts

const API_URL = '/api/v1'

export async function api<T>(url: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('token')
  console.log('current url:', `${API_URL}${url}`)
  const res = await fetch(`${API_URL}${url}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  })

  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`)
  }

  if (res.status === 204) {
    return undefined as T
  }

  return res.json() as Promise<T>
}
