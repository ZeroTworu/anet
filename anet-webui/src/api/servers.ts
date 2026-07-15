import { api } from './client'
import type { Server, CreateServerRequest } from '@/models/server'

/// Получить список всех зарегистрированных нод
export async function GetServers(): Promise<Server[]> {
    return api<Server[]>('/servers', {
        method: 'GET',
    })
}

/// Добавить новый физический сервер в базу данных
export async function CreateServer(data: CreateServerRequest): Promise<Server> {
    return api<Server>('/servers', {
        method: 'POST',
        body: JSON.stringify(data),
    })
}

/// Обновить параметры существующего сервера
export async function UpdateServer(id: string, data: Partial<CreateServerRequest>): Promise<Server> {
    return api<Server>(`/servers/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
    })
}

