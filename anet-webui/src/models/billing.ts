export type Currency = 'Rub' | 'Usd' | 'Eur' | 'Stars'

export type ProductType = 'GroupSubscription' | 'RateExtension' | 'Feature'

export type OrderStatus = 'Pending' | 'Paid' | 'Failed' | 'Cancelled' | 'Refunded'

export type PaymentSystem = 'FreeKassa' | 'Aaio' | 'YooMoney' | 'TelegramStars'

export interface AdminProduct {
  id: string
  name: string
  description: string
  price: number
  currency: Currency
  product_type: ProductType
  target_id: string | null
  sort_order: number
  badge: string | null
  metadata: Record<string, unknown> | null
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface CreateProductRequest {
  name: string
  description: string
  price: number
  currency: Currency
  product_type: ProductType
  target_id?: string | null
  sort_order?: number
  badge?: string | null
  metadata?: Record<string, unknown> | null
  is_active: boolean
}

export interface UpdateProductRequest {
  name?: string
  description?: string
  price?: number
  currency?: Currency
  product_type?: ProductType
  target_id?: string | null
  sort_order?: number
  badge?: string | null
  metadata?: Record<string, unknown> | null
  is_active?: boolean
}

export interface AdminOrder {
  id: string
  user_id: string
  product_id: string
  amount: number
  currency: Currency
  status: OrderStatus
  is_gift: boolean
  metadata: Record<string, unknown> | null
  created_at: string
  updated_at: string
}

export interface PaginatedOrdersResponse {
  items: AdminOrder[]
  total: number
  page: number
  page_size: number
}

export interface AdminTransaction {
  id: string
  order_id: string | null
  payment_system: PaymentSystem
  external_tx_id: string
  amount_received: number
  raw_request: unknown
  created_at: string
}

export interface PaginatedTransactionsResponse {
  items: AdminTransaction[]
  total: number
  page: number
  page_size: number
}
