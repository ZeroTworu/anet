// DTO статистики для таблиц узлов/пользователей и почасового графика.
export type NodeTrafficStat = {
  node_id: string
  name: string
  rx_bytes: number
  tx_bytes: number
}

export type UserTrafficStat = {
  user_id: string | null
  uid: string | null
  fingerprint: string
  rx_bytes: number
  tx_bytes: number
}

export type TrafficHistoryPoint = {
  bucket_start: string
  rx_bytes: number
  tx_bytes: number
}
