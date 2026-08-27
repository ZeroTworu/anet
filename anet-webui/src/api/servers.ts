import { api } from './client'
import type { Server, CreateServerRequest, NodeCommand, NodeCommandStatus, NodeCredential } from '@/models/server'


export async function GetServers(): Promise<Server[]> {
    return api<Server[]>('/servers', {
        method: 'GET',
    })
}

export async function CreateServer(data: CreateServerRequest): Promise<Server> {
    return api<Server>('/servers', {
        method: 'POST',
        data,
    })
}

export async function UpdateServer(id: string, data: Partial<CreateServerRequest>): Promise<Server> {
    return api<Server>(`/servers/${id}`, {
        method: 'PATCH',
        data,
    })
}

export async function SetNodeAdmission(id: string, acceptingConnections: boolean): Promise<NodeCommand> {
    return api<NodeCommand>(`/servers/${id}/commands/admission`, {
        method: 'POST',
        data: { accepting_connections: acceptingConnections },
    })
}

export async function GetNodeCommandStatus(serverId: string, commandId: string): Promise<NodeCommandStatus> {
    return api<NodeCommandStatus>(`/servers/${serverId}/commands/${commandId}`, {
        method: 'GET',
    })
}

export async function RotateNodeCredential(serverId: string): Promise<NodeCredential> {
    return api<NodeCredential>(`/servers/${serverId}/credentials`, {
        method: 'POST',
    })
}
