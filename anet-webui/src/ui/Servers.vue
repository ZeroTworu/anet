<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { GetServers } from '@/api/servers'
import type { Server } from '@/models/server'
import ServerModal from '@/components/ServerModal.vue'
import CreateServerModal from '@/components/CreateServerModal.vue'

const data = ref<Server[]>([])
const loading = ref(false)

// Управление модалками
const showCreateModal = ref(false)
const showEditModal = ref(false)
const selectedServer = ref<Server | null>(null)

let refreshTimer: number | undefined

const formatUptime = (seconds?: number) => {
  if (seconds === undefined) return '—'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return days > 0 ? `${days}d ${hours}h` : `${hours}h ${minutes}m`
}

const loadServers = async () => {
  loading.value = true
  try {
    data.value = await GetServers()
  } finally {
    loading.value = false
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
    <div class="d-flex justify-space-between align-center mb-5">
      <h2 style="margin: 0; font-weight: 600; font-size: 20px;">VPN Nodes (Servers)</h2>
      <v-btn color="primary" @click="showCreateModal = true"> Add Server </v-btn>
    </div>

    <div class="position-relative">
      <div class="table-container" v-if="data.length">
        <v-table :bordered="true" class="interactive-table">
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
              <v-chip :color="item.is_active ? 'success' : 'error'" size="small">
                {{ item.is_active ? 'ВКЛ' : 'ВЫКЛ' }}
              </v-chip>
            </td>
            <td>
              <v-chip
                  :color="item.runtime?.status === 'online' ? 'success' : 'error'"
                  size="small"
              >
                {{ item.runtime?.status === 'online' ? 'ONLINE' : 'OFFLINE' }}
              </v-chip>
              <div v-if="item.runtime" class="runtime-version">v{{ item.runtime.version }}</div>
            </td>
            <td>
              <v-chip :color="item.has_control_credential ? 'success' : 'warning'" size="small">
                {{ item.has_control_credential ? 'READY' : 'SETUP REQUIRED' }}
              </v-chip>
            </td>
            <td class="metric-col">{{ item.runtime?.active_connections ?? 0 }}</td>
            <td>
              <v-chip :color="item.runtime ? (item.runtime.accepting_connections ? 'success' : 'warning') : 'default'" size="small">
                {{ !item.runtime ? 'UNKNOWN' : item.runtime.accepting_connections ? 'OPEN' : 'CLOSED' }}
              </v-chip>
            </td>
            <td class="metric-col">{{ formatUptime(item.runtime?.uptime_seconds) }}</td>
          </tr>
          </tbody>
        </v-table>
      </div>
      <v-empty-state v-else title="Серверов пока нет" text="Добавьте первую ноду!" class="mt-10" />
    </div>

    <!-- Новая модалка создания сервера -->
    <CreateServerModal
        v-model="showCreateModal"
        @created="loadServers"
    />

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
/* Стили оставляем без изменений, они отличные */
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
