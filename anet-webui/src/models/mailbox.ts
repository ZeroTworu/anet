export interface ImapMailbox {
  id: string
  host: string
  port: number
  email: string
  has_client_password: boolean
  has_server_password: boolean
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface CreateImapMailboxRequest {
  host: string
  port: number
  email: string
  client_password: string
  server_password?: string | null
  is_active: boolean
}

export interface UpdateImapMailboxRequest {
  host: string
  port: number
  email: string
  client_password?: string | null
  server_password?: string | null
  is_active: boolean
}
