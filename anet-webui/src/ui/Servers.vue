<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { GetServers, CreateServer } from '@/api/servers'
import type { Server, CreateServerRequest } from '@/models/server'
import ServerModal from '@/components/ServerModal.vue'

const data = ref<Server[]>([])
const loading = ref(false)
const showCreate = ref(false)
const createLoading = ref(false)

const selectedServer = ref<Server | null>(null)
const showEditModal = ref(false)
let refreshTimer: number | undefined

const formatUptime = (seconds?: number) => {
  if (seconds === undefined) return '—'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return days > 0 ? `${days}d ${hours}h` : `${hours}h ${minutes}m`
}

const form = ref<CreateServerRequest>({
  name: '',
  dsn: 'quic://127.0.0.1:4519',
  public_key: '',
  ssh_user: 'hanyuu',
  is_active: true,
})

const loadServers = async () => {
  loading.value = true
  try {
    data.value = await GetServers()
  } finally {
    loading.value = false
  }
}

const handleCreate = async () => {
  createLoading.value = true
  try {
    await CreateServer(form.value)
    showCreate.value = false
    form.value = {
      name: '',
      dsn: 'quic://127.0.0.1:4519',
      public_key: '',
      ssh_user: 'hanyuu',
      is_active: true,
    }
    await loadServers()
  } finally {
    createLoading.value = false
  }
}

const openEdit = (server: Server) => {
  selectedServer.value = server
  showEditModal.value = true
}

const closeEditModal = () => {
  showEditModal.value = false
  selectedServer.value = null
}

onMounted(() => {
  loadServers()
  refreshTimer = window.setInterval(loadServers, 15_000)
})

onBeforeUnmount(() => {
  if (refreshTimer !== undefined) window.clearInterval(refreshTimer)
})
</script>

<template>
  <div style="padding: 24px; max-width: 1200px; margin: 0 auto;">
    <div justify="space-between" align="center" style="margin-bottom: 20px;">
      <h2 style="margin: 0; font-weight: 600; font-size: 20px;">VPN Nodes (Servers)</h2>
      <v-btn color="primary" @click="showCreate = true"> Add Server </v-btn>
    </div>

    <div class="position-relative">
      <div class="table-container" v-if="data.length">
        <v-table :bordered="true" :single-line="false" class="interactive-table">
          <thead>
          <tr>
            <th>Название</th>
            <th>DSN</th>
            <th>Configured</th>
            <th>Actual state</th>
            <th>Control plane</th>
            <th>Connections</th>
            <th>Admission</th>
            <th>Uptime</th>
          </tr>
          </thead>
          <tbody>
          <tr v-for="item in data" :key="item.id" @click="openEdit(item)" class="clickable-row">
            <td class="name-col">{{ item.name }}</td>
            <td class="addr-col">{{ item.dsn }}</td>
            <td>
              <v-chip  :color="item.is_active ? 'success' : 'error'" round size="small">
                {{ item.is_active ? 'ВКЛ' : 'ВЫКЛ' }}
              </v-chip>
            </td>
            <td>
              <v-chip
                   :color="item.runtime?.status === 'online' ? 'success' : 'error'"
                  round
                  size="small"
              >
                {{ item.runtime?.status === 'online' ? 'ONLINE' : 'OFFLINE' }}
              </v-chip>
              <div v-if="item.runtime" class="runtime-version">v{{ item.runtime.version }}</div>
            </td>
            <td>
              <v-chip  :color="item.has_control_credential ? 'success' : 'warning'" size="small">
                {{ item.has_control_credential ? 'READY' : 'SETUP REQUIRED' }}
              </v-chip>
            </td>
            <td class="metric-col">{{ item.runtime?.active_connections ?? 0 }}</td>
            <td>
              <v-chip  :color="item.runtime ? (item.runtime.accepting_connections ? 'success' : 'warning') : 'default'" size="small">
                {{ !item.runtime ? 'UNKNOWN' : item.runtime.accepting_connections ? 'OPEN' : 'CLOSED' }}
              </v-chip>
            </td>
            <td class="metric-col">{{ formatUptime(item.runtime?.uptime_seconds) }}</td>
          </tr>
          </tbody>
        </v-table>
      </div>
      <v-empty-state v-else description="Серверов пока нет. Добавьте первую ноду!" style="margin-top: 40px;" />
    </div>

    <!-- Модалка создания нового сервера -->
    <v-dialog v-model="showCreate" style="width: 650px;" title="Добавить физический сервер">
      <v-form>
        <div label="Название локации">
          <v-text-field v-model="form.name" placeholder="e.g. Germany VPS 1" />
        </div>

        <div label="DSN">
          <v-text-field v-model="form.dsn" placeholder="quic://host:4519 или wss://host:8080/socket" />
        </div>

        <div label="Публичный ключ сервера (server_pub_key)">
          <v-text-field v-model="form.public_key" placeholder="Из утилиты anet-keygen" />
        </div>

        <div label="Пользователь SSH (ssh_user)">
          <v-text-field v-model="form.ssh_user" placeholder="hanyuu" />
        </div>

        <div label="Активен (ВКЛ)">
          <v-switch v-model="form.is_active" />
        </div>
      </v-form>
      <div class="d-flex justify-end ga-4">
        <div justify="end">
          <v-btn @click="showCreate = false">Cancel</v-btn>
          <v-btn color="primary" :loading="createLoading" @click="handleCreate"> Add Node </v-btn>
        </div>
      </div>
    </v-dialog>

    <!-- Модалка редактирования существующего сервера -->
    <ServerModal
        v-model="showEditModal"
        :server="selectedServer"
        @updated="loadServers"
        @close="closeEditModal"
    />
  </div>
</template>

<style scoped>
.table-container {
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
  border: 1px solid #dcdcdc !important;
  overflow: hidden;
}

.interactive-table :deep(th) {
  background-color: #f5f5f7 !important;
  color: #1a1a1a !important;
  font-weight: 700 !important;
  border-bottom: 2px solid #c5c5c5 !important;
}

.interactive-table :deep(td) {
  border-bottom: 1px solid #dcdcdc !important;
  padding: 16px 20px !important;
}

.clickable-row {
  background-color: #ffffff !important;
  cursor: pointer;
  border-left: 4px solid transparent;
  transition: all 0.15s ease-in-out;
}

.clickable-row:nth-child(even) {
  background-color: #fcfcfc !important;
}

.clickable-row:hover {
  border-left: 4px solid #18a058 !important;
  background-color: #f0fdf4 !important;
}

.name-col {
  font-weight: 600 !important;
  color: #1a1a1a !important;
  font-size: 15px !important;
}

.addr-col {
  font-family: 'Fira Code', 'Courier New', Courier, monospace !important;
  color: #4a5568 !important;
}

.metric-col {
  font-family: 'Fira Code', 'Courier New', Courier, monospace;
  white-space: nowrap;
}

.runtime-version {
  margin-top: 4px;
  color: #64748b;
  font-family: monospace;
  font-size: 11px;
}

@media (prefers-color-scheme: dark) {
  .table-container {
    background: #18181c;
    border: 1px solid #333;
  }
  .interactive-table :deep(th) {
    background-color: #26262a !important;
    color: #fff !important;
    border-bottom: 2px solid #444 !important;
  }
  .interactive-table :deep(td) {
    border-bottom: 1px solid #333 !important;
  }
  .clickable-row {
    background-color: #18181c !important;
  }
  .clickable-row:nth-child(even) {
    background-color: #1c1c20 !important;
  }
  .clickable-row:hover {
    background-color: #1a3a2a !important;
    border-left: 4px solid #18a058 !important;
  }
  .name-col {
    color: #ffffff !important;
  }
  .addr-col {
    color: #cbd5e1 !important;
  }
}
</style>
