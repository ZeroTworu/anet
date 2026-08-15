// DTO пула, общий для редактора UI и resolver панели.
export type NodePoolMember = {
  server_id: string
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
