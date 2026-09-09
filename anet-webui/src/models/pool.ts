// DTO пула, общий для редактора UI и resolver панели.
export type ProtocolType = 'quic' | 'ssh' | 'vnc' | 'ws' | 'ahttp'

export type NodePoolMember = {
  server_id: string
  protocol: ProtocolType
  port_or_url?: string | null
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
