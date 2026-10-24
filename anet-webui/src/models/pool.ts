export type ProtocolType = 'quic' | 'ssh' | 'vnc' | 'ws' | 'ahttp' | 'wrtc' | 'doh'

export type NodePoolMember = {
  server_id: string
  protocol: ProtocolType
  port_or_url?: string | null
  wrtc_mode?: string | null
  doh_mode?: string | null
  weight: number
}

export type NodePool = {
  id: string
  name: string
  strategy: 'weighted' | 'least_connections'
  is_active: boolean
  members: NodePoolMember[]
}

export type SaveNodePoolRequest = Omit<NodePool, 'id'>
