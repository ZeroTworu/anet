<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { GetServers } from '@/api/servers'
import type { Server } from '@/models/server'
import ServerModal from '@/components/ServerModal.vue'
import CreateServerModal from '@/components/CreateServerModal.vue'

const data = ref<Server[]>([])
const loading = ref(false)
const searchQuery = ref('')

// Управление модалками
const showCreateModal = ref(false)
const showEditModal = ref(false)
const selectedServer = ref<Server | null>(null)

let refreshTimer: number | undefined

const headers = [
  { title: 'Название', key: 'name', sortable: true },
  { title: 'Адрес / Домен', key: 'address', sortable: true }, // Заменили dsn на address
  { title: 'Configured', key: 'is_active', sortable: true, align: 'center' as const },
  { title: 'Actual state', key: 'runtime.status', sortable: true, align: 'center' as const },
  { title: 'Control plane', key: 'has_control_credential', sortable: true, align: 'center' as const },
  { title: 'Connections', key: 'runtime.active_connections', sortable: true, align: 'end' as const },
  { title: 'Admission', key: 'runtime.accepting_connections', sortable: true, align: 'center' as const },
  { title: 'Uptime', key: 'runtime.uptime_seconds', sortable: true, align: 'end' as const },
]

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
  <v-container max-width="1400" class="servers-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-5">
      <div>
        <h2 class="text-h6 font-weight-bold ma-0">VPN Nodes (Servers)</h2>
        <span class="text-caption text-medium-emphasis">Управление физическими серверами и нодами доступа</span>
      </div>
      <div class="d-flex align-center ga-3">
        <v-text-field
            v-model="searchQuery"
            prepend-inner-icon="mdi-magnify"
            label="Поиск по названию или IP..."
            variant="outlined"
            density="compact"
            hide-details
            single-line
            style="width: 280px"
        />
        <v-btn color="primary" @click="showCreateModal = true"> Add Server </v-btn>
      </div>
    </div>

    <v-data-table
        :headers="headers"
        :items="data"
        :search="searchQuery"
        :loading="loading"
        :items-per-page="10"
        :items-per-page-options="[10, 20, 50]"
        items-per-page-text="Строк на странице"
        loading-text="Загрузка нод…"
        no-data-text="Серверов пока нет — добавьте первую ноду!"
        density="comfortable"
        class="servers-table"
        hover
        @click:row="(_: unknown, data: { item: Server }) => openEdit(data.item)"
    >
      <template #item.name="{ item }">
        <span class="name-col">{{ item.name }}</span>
      </template>

      <!-- Выводим адрес вместо dsn -->
      <template #item.address="{ item }">
        <span class="addr-col">{{ item.address }}</span>
      </template>

      <template #item.is_active="{ item }">
        <v-chip :color="item.is_active ? 'success' : 'error'" size="small">
          {{ item.is_active ? 'ВКЛ' : 'ВЫКЛ' }}
        </v-chip>
      </template>

      <template #item.runtime.status="{ item }">
        <div class="state-cell">
          <v-chip :color="item.runtime?.status === 'online' ? 'success' : 'error'" size="small">
            {{ item.runtime?.status === 'online' ? 'ONLINE' : 'OFFLINE' }}
          </v-chip>
          <div v-if="item.runtime" class="runtime-version">v{{ item.runtime.version }}</div>
        </div>
      </template>

      <template #item.has_control_credential="{ item }">
        <v-chip :color="item.has_control_credential ? 'success' : 'warning'" size="small">
          {{ item.has_control_credential ? 'READY' : 'SETUP REQUIRED' }}
        </v-chip>
      </template>

      <template #item.runtime.active_connections="{ item }">
        <span class="metric-col">{{ item.runtime?.active_connections ?? 0 }}</span>
      </template>

      <template #item.runtime.accepting_connections="{ item }">
        <v-chip
            :color="item.runtime ? (item.runtime.accepting_connections ? 'success' : 'warning') : 'default'"
            size="small"
        >
          {{ !item.runtime ? 'UNKNOWN' : item.runtime.accepting_connections ? 'OPEN' : 'CLOSED' }}
        </v-chip>
      </template>

      <template #item.runtime.uptime_seconds="{ item }">
        <span class="metric-col">{{ formatUptime(item.runtime?.uptime_seconds) }}</span>
      </template>
    </v-data-table>

    <CreateServerModal
        v-model="showCreateModal"
        @created="loadServers"
    />

    <ServerModal
        v-model="showEditModal"
        :server="selectedServer"
        @updated="loadServers"
        @close="closeEditModal"
    />
  </v-container>
</template>

<style scoped>
.servers-page { padding: 24px; }
.servers-table { border-radius: 10px; }
.servers-table :deep(tbody tr) { cursor: pointer; }
.servers-table :deep(tbody tr:hover) { background: rgba(43, 184, 148, .07) !important; }
.name-col { font-weight: 600; font-size: 15px; }
.addr-col { font-family: 'Fira Code', 'Courier New', Courier, monospace; color: #9aa5a0; }
.metric-col { font-family: 'Fira Code', 'Courier New', Courier, monospace; white-space: nowrap; }
.state-cell { display: flex; flex-direction: column; align-items: center; gap: 4px; }
.runtime-version { color: #7a857f; font-family: monospace; font-size: 11px; }
</style>
