// src/api/auth.ts

import { api } from './client'

type LoginRequest = {
  login: string
  password: string
}

type LoginResponse = {
  access_token: string
}

export async function login(data: LoginRequest): Promise<string> {
  const res = await api<LoginResponse>('/login', {
    method: 'POST',
    body: JSON.stringify(data)
  })

  return res.access_token
}