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
  { title: 'Действия', key: 'actions', sortable: false, align: 'center' as const },
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
  <v-container fluid class="servers-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-4">
      <v-list-item
        class="px-0"
        subtitle="Управление физическими серверами, токенами управления и состоянием нод доступа"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">VPN Nodes (Серверы)</h1>
        </template>
      </v-list-item>
    </div>

    <div class="d-flex justify-space-between align-center mb-4">
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
      <v-btn color="primary" prepend-icon="mdi-plus" @click="showCreateModal = true">
        + ДОБАВИТЬ СЕРВЕР
      </v-btn>
    </div>

    <v-data-table
      :headers="headers"
      :items="data"
      :search="searchQuery"
      :loading="loading"
      :items-per-page="10"
      :items-per-page-options="[10, 20, 50]"
      items-per-page-text="Items per page:"
      loading-text="Загрузка нод…"
      no-data-text="Серверов пока нет — добавьте первую ноду!"
      density="comfortable"
      class="border rounded-lg"
      hover
      @click:row="(_: unknown, data: { item: Server }) => openEdit(data.item)"
    >
      <template #item.name="{ item }">
        <span class="font-weight-bold">{{ item.name }}</span>
      </template>

      <template #item.address="{ item }">
        <code class="font-weight-medium text-primary">{{ item.address }}</code>
      </template>

      <template #item.is_active="{ item }">
        <v-chip :color="item.is_active ? 'success' : 'default'" size="small">
          {{ item.is_active ? 'ACTIVE' : 'OFF' }}
        </v-chip>
      </template>

      <template #item.runtime.status="{ item }">
        <div class="d-flex flex-column align-center ga-1">
          <v-chip :color="item.runtime?.status === 'online' ? 'success' : 'error'" size="small">
            {{ item.runtime?.status === 'online' ? 'ONLINE' : 'OFFLINE' }}
          </v-chip>
          <div v-if="item.runtime" class="text-caption text-medium-emphasis">v{{ item.runtime.version }}</div>
        </div>
      </template>

      <template #item.has_control_credential="{ item }">
        <v-chip :color="item.has_control_credential ? 'success' : 'warning'" variant="tonal" size="small">
          {{ item.has_control_credential ? 'READY' : 'REQUIRED' }}
        </v-chip>
      </template>

      <template #item.runtime.active_connections="{ item }">
        <v-chip size="small" variant="tonal" color="success" prepend-icon="mdi-account-multiple">
          {{ item.runtime?.active_connections ?? 0 }}
        </v-chip>
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
        <span class="text-caption text-medium-emphasis">{{ formatUptime(item.runtime?.uptime_seconds) }}</span>
      </template>

      <template #item.actions="{ item }">
        <div class="d-flex ga-1 justify-center flex-nowrap" @click.stop>
          <v-btn
            icon="mdi-pencil"
            size="small"
            variant="text"
            title="Редактировать сервер"
            @click="openEdit(item)"
          />
        </div>
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
.servers-page {
  padding: 24px;
}
</style>
