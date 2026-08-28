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

export type ActiveConnection = {
  user_id: string
  username: string
  server_id: string
  server_name: string
  rx_bytes: number
  tx_bytes: number
  connection_count: number
  protocol: string
}
