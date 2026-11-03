import { api } from './client'
import type { CreateImapMailboxRequest, ImapMailbox, UpdateImapMailboxRequest } from '@/models/mailbox'

export async function GetMailboxes(): Promise<ImapMailbox[]> {
  return api<ImapMailbox[]>('/mailboxes', {
    method: 'GET',
  })
}

export async function CreateMailbox(data: CreateImapMailboxRequest): Promise<ImapMailbox> {
  return api<ImapMailbox>('/mailboxes', {
    method: 'POST',
    data,
  })
}

export async function UpdateMailbox(id: string, data: UpdateImapMailboxRequest): Promise<ImapMailbox> {
  return api<ImapMailbox>(`/mailboxes/${id}`, {
    method: 'PUT',
    data,
  })
}

export async function DeleteMailbox(id: string): Promise<boolean> {
  return api<boolean>(`/mailboxes/${id}`, {
    method: 'DELETE',
  })
}
