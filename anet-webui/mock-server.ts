import type { IncomingMessage, ServerResponse } from 'node:http'

interface UserItem {
  id: string
  fingerprint: string
  uid: string
  is_active: boolean
  created_at: string
  rate: { id: string; sessions: number; date_end: string } | null
  static_ip: string | null
  server_ids: string[]
  pool_ids: string[]
  route_map_id: string | null
  group_id: string | null
}

const mockServers = [
  {
    id: 'srv-fra-1',
    name: 'Frankfurt Core 01',
    address: '194.135.80.14:443',
    public_key: 'xK49pQ817abcde1234567890pubkey1=',
    ssh_user: 'root',
    is_active: true,
    has_control_credential: true,
    quic_port: 443,
    ssh_port: 2222,
    vnc_port: null,
    websocket_url: 'wss://fra-01.anet.net/ws',
    ahttp_url: 'https://fra-01.anet.net/vpn',
    runtime: {
      status: 'online',
      last_seen_at: new Date().toISOString(),
      version: '1.4.2',
      uptime_seconds: 864200,
      active_connections: 142,
      accepting_connections: true,
    },
  },
  {
    id: 'srv-ams-2',
    name: 'Amsterdam Edge 02',
    address: '185.220.101.5:443',
    public_key: 'mQ817xK49xyz9876543210pubkey2=',
    ssh_user: 'root',
    is_active: true,
    has_control_credential: true,
    quic_port: 443,
    ssh_port: 2222,
    vnc_port: null,
    websocket_url: 'wss://ams-02.anet.net/ws',
    ahttp_url: 'https://ams-02.anet.net/vpn',
    runtime: {
      status: 'online',
      last_seen_at: new Date().toISOString(),
      version: '1.4.2',
      uptime_seconds: 432100,
      active_connections: 89,
      accepting_connections: true,
    },
  },
  {
    id: 'srv-hel-3',
    name: 'Helsinki Fallback 03',
    address: '95.217.44.12:443',
    public_key: 'pQ817mQ8qwert555544433pubkey3=',
    ssh_user: 'admin',
    is_active: true,
    has_control_credential: true,
    quic_port: 443,
    ssh_port: 22,
    vnc_port: null,
    websocket_url: null,
    ahttp_url: null,
    runtime: {
      status: 'offline',
      last_seen_at: new Date(Date.now() - 3600000).toISOString(),
      version: '1.4.1',
      uptime_seconds: 0,
      active_connections: 0,
      accepting_connections: false,
    },
  },
]

const mockUsers: UserItem[] = [
  {
    id: 'usr-1',
    fingerprint: 'a8b7c6d5e4f3a2b10987654321abcdef',
    uid: 'alice@anet.local',
    is_active: true,
    created_at: new Date(Date.now() - 86400000 * 30).toISOString(),
    rate: { id: 'rate-1', sessions: 5, date_end: '2026-12-31' },
    static_ip: '10.8.0.2',
    server_ids: ['srv-fra-1', 'srv-ams-2'],
    pool_ids: ['pool-1'],
    route_map_id: 'rm-1',
    group_id: 'grp-1',
  },
  {
    id: 'usr-2',
    fingerprint: '112233445566778899aabbccddeeff00',
    uid: 'bob@anet.local',
    is_active: true,
    created_at: new Date(Date.now() - 86400000 * 15).toISOString(),
    rate: { id: 'rate-2', sessions: 2, date_end: '2026-10-31' },
    static_ip: '10.8.0.3',
    server_ids: ['srv-fra-1'],
    pool_ids: ['pool-1'],
    route_map_id: null,
    group_id: 'grp-1',
  },
  {
    id: 'usr-3',
    fingerprint: 'ffeeeeddddccccbbbbaaaa9999888877',
    uid: 'charlie@anet.local',
    is_active: false,
    created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
    rate: null,
    static_ip: null,
    server_ids: ['srv-ams-2'],
    pool_ids: [],
    route_map_id: null,
    group_id: null,
  },
]

const mockPools = [
  {
    id: 'pool-1',
    name: 'EU High-Speed Pool',
    strategy: 'least_connections',
    is_active: true,
    members: [
      { server_id: 'srv-fra-1', protocol: 'quic', port_or_url: '443', weight: 100 },
      { server_id: 'srv-ams-2', protocol: 'quic', port_or_url: '443', weight: 80 },
    ],
  },
]

const mockRouteMaps = [
  {
    id: 'rm-1',
    name: 'Corporate Bypass & Cloud',
    description: 'Split tunneling for internal corporate services and direct internet',
    default_action: 'direct',
    is_active: true,
    revision: 3,
    rules: [
      { id: 'rule-1', position: 1, match_type: 'cidr', match_value: '10.0.0.0/8', action: 'tunnel' },
      { id: 'rule-2', position: 2, match_type: 'cidr', match_value: '192.168.0.0/16', action: 'tunnel' },
      { id: 'rule-3', position: 3, match_type: 'application', match_value: 'slack.exe', action: 'direct' },
    ],
    rules_count: 3,
  },
]

const mockGroups = [
  {
    id: 'grp-1',
    name: 'Engineering Staff',
    traffic_limit: 500, // GB
    speed_limit: 100, // Mbps
    sessions_limit: 5,
    duration_days: 365,
    pool_ids: ['pool-1'],
    created_at: new Date(Date.now() - 86400000 * 45).toISOString(),
    updated_at: new Date().toISOString(),
    user_count: 2,
  },
  {
    id: 'grp-2',
    name: 'Contractors',
    traffic_limit: 50,
    speed_limit: 25,
    sessions_limit: 2,
    duration_days: 90,
    pool_ids: ['pool-1'],
    created_at: new Date(Date.now() - 86400000 * 20).toISOString(),
    updated_at: new Date().toISOString(),
    user_count: 0,
  },
]

function readBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
    })
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {})
      } catch {
        resolve({})
      }
    })
  })
}

function sendJson(res: ServerResponse, status: number, data: any) {
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(data))
}

export function handleMockApi(req: IncomingMessage, res: ServerResponse): boolean {
  const urlObj = new URL(req.url || '/', 'http://localhost')
  const path = urlObj.pathname
  const method = req.method?.toUpperCase() || 'GET'

  if (!path.startsWith('/api/v1')) {
    return false
  }

  const endpoint = path.replace('/api/v1', '')

  // 1. Auth: /login
  if (endpoint === '/login' && method === 'POST') {
    readBody(req).then((_body) => {
      sendJson(res, 200, {
        access_token: 'anet-demo-jwt-session-' + Date.now(),
      })
    })
    return true
  }

  // 2. Servers
  if (endpoint === '/servers' && method === 'GET') {
    sendJson(res, 200, mockServers)
    return true
  }
  if (endpoint === '/servers' && method === 'POST') {
    readBody(req).then((body) => {
      const newServer = {
        id: 'srv-' + Math.random().toString(36).substring(2, 7),
        name: body.name || 'New Node',
        address: body.address || '127.0.0.1:443',
        public_key: body.public_key || 'mock-pubkey',
        ssh_user: body.ssh_user || 'root',
        is_active: body.is_active !== undefined ? body.is_active : true,
        has_control_credential: true,
        quic_port: body.quic_port || 443,
        ssh_port: body.ssh_port || 22,
        vnc_port: body.vnc_port || null,
        websocket_url: body.websocket_url || null,
        ahttp_url: body.ahttp_url || null,
        runtime: {
          status: 'online',
          last_seen_at: new Date().toISOString(),
          version: '1.4.2',
          uptime_seconds: 3600,
          active_connections: 0,
          accepting_connections: true,
        },
      }
      mockServers.push(newServer as any)
      sendJson(res, 201, newServer)
    })
    return true
  }
  if (endpoint.startsWith('/servers/') && endpoint.includes('/commands/admission') && method === 'POST') {
    readBody(req).then((body) => {
      const serverId = endpoint.split('/')[2]
      const server = mockServers.find((s) => s.id === serverId)
      if (server && server.runtime) {
        server.runtime.accepting_connections = !!body.accepting_connections
      }
      sendJson(res, 200, {
        command_id: 'cmd-' + Date.now(),
        command_type: 'admission',
        accepting_connections: body.accepting_connections,
      })
    })
    return true
  }
  if (endpoint.startsWith('/servers/') && endpoint.includes('/commands/') && method === 'GET') {
    const parts = endpoint.split('/')
    sendJson(res, 200, {
      command_id: parts[4] || 'cmd-1',
      server_id: parts[2],
      command_type: 'admission',
      status: 'succeeded',
      accepting_connections: true,
      created_at: new Date().toISOString(),
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      error: null,
    })
    return true
  }
  if (endpoint.startsWith('/servers/') && endpoint.endsWith('/credentials') && method === 'POST') {
    const serverId = endpoint.split('/')[2]
    sendJson(res, 200, {
      node_id: serverId,
      token: 'anet_ctrl_tok_' + Math.random().toString(36).substring(2, 12),
    })
    return true
  }
  if (endpoint.startsWith('/servers/') && method === 'PATCH') {
    const serverId = endpoint.split('/')[2]
    readBody(req).then((body) => {
      const s = mockServers.find((srv) => srv.id === serverId)
      if (s) Object.assign(s, body)
      sendJson(res, 200, s || {})
    })
    return true
  }

  // 3. Users: /users, /user/:id, /add, /regenerate/:id
  if (endpoint.startsWith('/users') && method === 'GET') {
    const search = urlObj.searchParams.get('search')?.toLowerCase()
    let filtered = mockUsers
    if (search) {
      filtered = mockUsers.filter((u) => u.uid.toLowerCase().includes(search) || u.fingerprint.includes(search))
    }
    sendJson(res, 200, {
      items: filtered,
      total: filtered.length,
    })
    return true
  }
  if (endpoint.startsWith('/user/') && method === 'GET') {
    const id = endpoint.replace('/user/', '')
    const u = mockUsers.find((user) => user.id === id)
    sendJson(res, 200, u || mockUsers[0])
    return true
  }
  if (endpoint.startsWith('/user/') && method === 'PATCH') {
    const id = endpoint.replace('/user/', '')
    readBody(req).then((body) => {
      const u = mockUsers.find((user) => user.id === id)
      if (u) {
        if (body.uid) u.uid = body.uid
        if (body.is_active !== undefined) u.is_active = body.is_active
        if (body.static_ip !== undefined) u.static_ip = body.static_ip
        if (body.server_ids) u.server_ids = body.server_ids
        if (body.pool_ids) u.pool_ids = body.pool_ids
        if (body.clear_route_map) u.route_map_id = null
        else if (body.route_map_id) u.route_map_id = body.route_map_id
        if (body.clear_group) u.group_id = null
        else if (body.group_id) u.group_id = body.group_id
      }
      sendJson(res, 200, {
        id,
        uid: u?.uid || 'user',
        fingerprint: u?.fingerprint || 'fp-updated',
        private_key: 'anet-privkey-demo',
        public_key: 'anet-pubkey-demo',
      })
    })
    return true
  }
  if (endpoint === '/add' && method === 'POST') {
    readBody(req).then((body) => {
      const newUser: UserItem = {
        id: 'usr-' + Math.random().toString(36).substring(2, 7),
        fingerprint: Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        uid: body.uid || 'new_user',
        is_active: true,
        created_at: new Date().toISOString(),
        rate: { id: 'rate-' + Date.now(), sessions: 3, date_end: '2026-12-31' },
        static_ip: '10.8.0.' + (mockUsers.length + 10),
        server_ids: body.server_ids || ['srv-fra-1'],
        pool_ids: body.pool_ids || [],
        route_map_id: body.route_map_id || null,
        group_id: body.group_id || null,
      }
      mockUsers.unshift(newUser)
      sendJson(res, 201, newUser)
    })
    return true
  }
  if (endpoint.startsWith('/regenerate/') && method === 'POST') {
    const id = endpoint.replace('/regenerate/', '')
    const u = mockUsers.find((user) => user.id === id)
    sendJson(res, 200, {
      id,
      uid: u?.uid || 'user',
      fingerprint: u?.fingerprint || 'fp-demo',
      private_key: 'mock-private-key-' + Math.random().toString(36),
      public_key: 'mock-public-key-' + Math.random().toString(36),
    })
    return true
  }

  // 4. Rate: /rate/:id, /addrate
  if (endpoint.startsWith('/rate/') && method === 'PATCH') {
    const id = endpoint.replace('/rate/', '')
    readBody(req).then((body) => {
      sendJson(res, 200, {
        id,
        sessions: body.sessions || 3,
        date_end: body.date_end || '2026-12-31',
      })
    })
    return true
  }
  if (endpoint.startsWith('/addrate') && method === 'POST') {
    readBody(req).then((body) => {
      sendJson(res, 200, {
        id: 'rate-' + Date.now(),
        sessions: body.sessions || 3,
        date_end: body.date_end || '2026-12-31',
      })
    })
    return true
  }

  // 5. Pools: /pools
  if (endpoint === '/pools' && method === 'GET') {
    sendJson(res, 200, mockPools)
    return true
  }
  if (endpoint === '/pools' && method === 'POST') {
    readBody(req).then((body) => {
      const newPool = {
        id: 'pool-' + Math.random().toString(36).substring(2, 7),
        ...body,
      }
      mockPools.push(newPool)
      sendJson(res, 201, newPool)
    })
    return true
  }
  if (endpoint.startsWith('/pools/') && method === 'PATCH') {
    const id = endpoint.replace('/pools/', '')
    readBody(req).then((body) => {
      const p = mockPools.find((pool) => pool.id === id)
      if (p) Object.assign(p, body)
      sendJson(res, 200, p || {})
    })
    return true
  }
  if (endpoint.startsWith('/pools/') && method === 'DELETE') {
    const id = endpoint.replace('/pools/', '')
    const idx = mockPools.findIndex((pool) => pool.id === id)
    if (idx !== -1) mockPools.splice(idx, 1)
    sendJson(res, 200, {})
    return true
  }

  // 6. Route Maps: /route-maps
  if (endpoint === '/route-maps' && method === 'GET') {
    sendJson(res, 200, mockRouteMaps)
    return true
  }
  if (endpoint === '/route-maps' && method === 'POST') {
    readBody(req).then((body) => {
      const newMap = {
        id: 'rm-' + Math.random().toString(36).substring(2, 7),
        revision: 1,
        rules_count: (body.rules || []).length,
        ...body,
      }
      mockRouteMaps.push(newMap)
      sendJson(res, 201, newMap)
    })
    return true
  }
  if (endpoint.startsWith('/route-maps/') && method === 'PATCH') {
    const id = endpoint.replace('/route-maps/', '')
    readBody(req).then((body) => {
      const m = mockRouteMaps.find((map) => map.id === id)
      if (m) {
        Object.assign(m, body)
        m.revision = (m.revision || 1) + 1
        m.rules_count = (m.rules || []).length
      }
      sendJson(res, 200, m || {})
    })
    return true
  }
  if (endpoint.startsWith('/route-maps/') && method === 'DELETE') {
    const id = endpoint.replace('/route-maps/', '')
    const idx = mockRouteMaps.findIndex((map) => map.id === id)
    if (idx !== -1) mockRouteMaps.splice(idx, 1)
    sendJson(res, 200, {})
    return true
  }

  // 7. Groups: /groups
  if (endpoint === '/groups' && method === 'GET') {
    sendJson(res, 200, mockGroups)
    return true
  }
  if (endpoint.startsWith('/groups/') && endpoint.endsWith('/pools') && method === 'GET') {
    const groupId = endpoint.split('/')[2]
    const grp = mockGroups.find((g) => g.id === groupId)
    const pools = mockPools.filter((p) => grp?.pool_ids?.includes(p.id))
    sendJson(res, 200, pools)
    return true
  }
  if (endpoint.startsWith('/groups/') && endpoint.endsWith('/pools') && method === 'PUT') {
    const groupId = endpoint.split('/')[2]
    readBody(req).then((body) => {
      const grp = mockGroups.find((g) => g.id === groupId)
      if (grp) grp.pool_ids = body.pool_ids || []
      sendJson(res, 200, grp?.pool_ids || [])
    })
    return true
  }
  if (endpoint.startsWith('/groups/') && endpoint.includes('/members') && method === 'GET') {
    const groupId = endpoint.split('/')[2]
    const members = mockUsers.filter((u) => u.group_id === groupId)
    sendJson(res, 200, {
      items: members,
      total: members.length,
    })
    return true
  }
  if (endpoint.startsWith('/groups/') && endpoint.includes('/members') && method === 'POST') {
    const groupId = endpoint.split('/')[2]
    readBody(req).then((body) => {
      const user = mockUsers.find((u) => u.id === body.user_id)
      if (user) user.group_id = groupId
      sendJson(res, 200, {})
    })
    return true
  }
  if (endpoint.startsWith('/groups/') && endpoint.includes('/members') && method === 'DELETE') {
    const parts = endpoint.split('/')
    const userId = parts[4]
    const user = mockUsers.find((u) => u.id === userId)
    if (user) user.group_id = null
    sendJson(res, 200, {})
    return true
  }
  if (endpoint.startsWith('/groups/') && method === 'GET') {
    const id = endpoint.replace('/groups/', '')
    const g = mockGroups.find((grp) => grp.id === id)
    sendJson(res, 200, g || mockGroups[0])
    return true
  }
  if (endpoint === '/groups' && method === 'POST') {
    readBody(req).then((body) => {
      const newGrp = {
        id: 'grp-' + Math.random().toString(36).substring(2, 7),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        user_count: 0,
        ...body,
      }
      mockGroups.push(newGrp)
      sendJson(res, 201, newGrp)
    })
    return true
  }
  if (endpoint.startsWith('/groups/') && method === 'PATCH') {
    const id = endpoint.replace('/groups/', '')
    readBody(req).then((body) => {
      const g = mockGroups.find((grp) => grp.id === id)
      if (g) {
        Object.assign(g, body)
        g.updated_at = new Date().toISOString()
      }
      sendJson(res, 200, g || {})
    })
    return true
  }
  if (endpoint.startsWith('/groups/') && method === 'DELETE') {
    const id = endpoint.replace('/groups/', '')
    const idx = mockGroups.findIndex((grp) => grp.id === id)
    if (idx !== -1) mockGroups.splice(idx, 1)
    sendJson(res, 200, {})
    return true
  }

  // 8. Statistics: /statistics/*
  if (endpoint === '/statistics/nodes' && method === 'GET') {
    sendJson(res, 200, [
      {
        node_id: 'srv-fra-1',
        name: 'Frankfurt Core 01',
        rx_bytes: 48291048201,
        tx_bytes: 94810294812,
      },
      {
        node_id: 'srv-ams-2',
        name: 'Amsterdam Edge 02',
        rx_bytes: 23194018201,
        tx_bytes: 41829104821,
      },
      {
        node_id: 'srv-hel-3',
        name: 'Helsinki Fallback 03',
        rx_bytes: 1420914,
        tx_bytes: 2940182,
      },
    ])
    return true
  }
  if (endpoint === '/statistics/users' && method === 'GET') {
    sendJson(res, 200, [
      {
        user_id: 'usr-1',
        uid: 'alice@anet.local',
        fingerprint: 'a8b7c6d5e4f3a2b10987654321abcdef',
        rx_bytes: 24109401820,
        tx_bytes: 52194018201,
      },
      {
        user_id: 'usr-2',
        uid: 'bob@anet.local',
        fingerprint: '112233445566778899aabbccddeeff00',
        rx_bytes: 9104829102,
        tx_bytes: 18491048102,
      },
    ])
    return true
  }
  if (endpoint === '/statistics/active-connections' && method === 'GET') {
    sendJson(res, 200, [
      {
        user_id: 'usr-1',
        username: 'alice@anet.local',
        server_id: 'srv-fra-1',
        server_name: 'Frankfurt Core 01',
        rx_bytes: 142019482,
        tx_bytes: 512048291,
        connection_count: 2,
        protocol: 'quic',
        fingerprint: 'a8b7c6d5e4f3a2b10987654321abcdef',
      },
      {
        user_id: 'usr-2',
        username: 'bob@anet.local',
        server_id: 'srv-ams-2',
        server_name: 'Amsterdam Edge 02',
        rx_bytes: 48201948,
        tx_bytes: 112048291,
        connection_count: 1,
        protocol: 'ahttp',
        fingerprint: '112233445566778899aabbccddeeff00',
      },
    ])
    return true
  }
  if (endpoint.startsWith('/statistics/traffic/history') && method === 'GET') {
    const points = []
    const now = Date.now()
    const hours = parseInt(urlObj.searchParams.get('hours') || '24', 10)
    for (let i = hours; i >= 0; i--) {
      const bucketTime = new Date(now - i * 3600000).toISOString()
      points.push({
        bucket_start: bucketTime,
        rx_bytes: Math.floor(100000000 + Math.random() * 500000000),
        tx_bytes: Math.floor(250000000 + Math.random() * 1200000000),
      })
    }
    sendJson(res, 200, points)
    return true
  }

  // Fallback for any other /api/v1/* request
  sendJson(res, 200, { ok: true })
  return true
}
