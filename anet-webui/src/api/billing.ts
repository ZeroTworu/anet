import { api } from './client'
import { toQuery } from '@/utils'
import type {
  AdminProduct,
  CreateProductRequest,
  OrderStatus,
  PaginatedOrdersResponse,
  PaginatedTransactionsResponse,
  UpdateProductRequest,
} from '@/models/billing'

export const GetAdminProducts = () => api<AdminProduct[]>('/admin/products')

export const CreateAdminProduct = (payload: CreateProductRequest) =>
  api<AdminProduct>('/admin/products', {
    method: 'POST',
    data: payload,
  })

export const UpdateAdminProduct = (id: string, payload: UpdateProductRequest) =>
  api<AdminProduct>(`/admin/products/${id}`, {
    method: 'PATCH',
    data: payload,
  })

export const DeleteAdminProduct = (id: string) =>
  api<boolean>(`/admin/products/${id}`, {
    method: 'DELETE',
  })

export const GetAdminOrders = (page = 1, page_size = 20, status?: OrderStatus | null) =>
  api<PaginatedOrdersResponse>(
    `/admin/orders?${toQuery({
      page,
      page_size,
      status: status || undefined,
    })}`,
  )

export const GetAdminTransactions = (page = 1, page_size = 20) =>
  api<PaginatedTransactionsResponse>(
    `/admin/transactions?${toQuery({
      page,
      page_size,
    })}`,
  )
