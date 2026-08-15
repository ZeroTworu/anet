import axios, { type AxiosRequestConfig } from 'axios'
import router from '@/router'

const client = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

client.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

client.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      if (router.currentRoute.value.path !== '/') {
        window.location.assign('/')
      }
    }
    return Promise.reject(error)
  },
)

export async function api<T>(url: string, config: AxiosRequestConfig = {}): Promise<T> {
  const response = await client.request<T>({ url, ...config })
  return response.data
}
