export type Server = {
    id: string
    name: string
    address: string
    public_key: string
    quic_port: number | null
    ssh_port: number | null
    vnc_port: number | null
    ssh_user: string | null
}

export type CreateServerRequest = {
    name: string
    address: string
    public_key: string
    quic_port: number | null
    ssh_port: number | null
    vnc_port: number | null
    ssh_user: string | null
}
