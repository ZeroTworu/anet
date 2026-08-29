<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { DeletePool, GetPools } from '@/api/pools'
import { GetServers } from '@/api/servers'
import type { NodePool } from '@/models/pool'
import type { Server } from '@/models/server'
import PoolModal from '@/components/PoolModal.vue'

const pools = ref<NodePool[]>([])
const servers = ref<Server[]>([])
const loading = ref(false)
const searchQuery = ref('')

const showEditor = ref(false)
const selectedPool = ref<NodePool | null>(null)

const serverById = computed(() => new Map(servers.value.map(server => [server.id, server])))

const headers = [
  { title: 'Название пула', key: 'name', sortable: true },
  { title: 'Стратегия балансировки', key: 'strategy', sortable: true },
  { title: 'Статус', key: 'is_active', sortable: true, align: 'center' as const },
  { title: 'Узлы пула (Вес)', key: 'members', sortable: false },
  { title: 'Действия', key: 'actions', sortable: false, align: 'center' as const },
]

const load = async () => {
  loading.value = true
  try {
    const [poolsData, serversData] = await Promise.all([GetPools(), GetServers()])
    pools.value = poolsData
    servers.value = serversData
  } finally {
    loading.value = false
  }
}

const openCreate = () => {
  selectedPool.value = null
  showEditor.value = true
}

const openEdit = (pool: NodePool) => {
  selectedPool.value = pool
  showEditor.value = true
}

const removePool = async (id: string) => {
  if (!confirm('Вы уверены, что хотите удалить этот pool? Все назначения пользователей будут сброшены.')) return
  await DeletePool(id)
  await load()
}

onMounted(load)
</script>

<template>
  <v-container max-width="1400" class="pools-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-5">
      <v-list-item
          class="px-0"
          subtitle="Группы узлов и стратегия выбора entry point"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">Node Pools</h1>
        </template>
      </v-list-item>
      <div class="d-flex align-center ga-3">
        <v-text-field
            v-model="searchQuery"
            prepend-inner-icon="mdi-magnify"
            label="Поиск по пулам..."
            variant="outlined"
            density="compact"
            hide-details
            single-line
            style="width: 280px"
        />
        <v-btn color="primary" @click="openCreate">Создать пул</v-btn>
      </div>
    </div>

    <v-data-table
        :headers="headers"
        :items="pools"
        :search="searchQuery"
        :loading="loading"
        :items-per-page="10"
        :items-per-page-options="[10, 20, 50]"
        items-per-page-text="Строк на странице"
        loading-text="Загрузка пулов балансировки…"
        no-data-text="Пулов пока нет — создайте первый!"
        density="comfortable"
        class="pools-table border rounded-lg"
        hover
        @click:row="(_: unknown, data: { item: NodePool }) => openEdit(data.item)"
    >
      <template #item.name="{ item }">
        <span class="pool-name-col">{{ item.name }}</span>
      </template>

      <template #item.strategy="{ item }">
        <span>{{ item.strategy === 'weighted' ? 'Weighted rendezvous' : 'Least connections' }}</span>
      </template>

      <template #item.is_active="{ item }">
        <v-chip :color="item.is_active ? 'success' : 'default'" size="small">
          {{ item.is_active ? 'ACTIVE' : 'DISABLED' }}
        </v-chip>
      </template>

      <template #item.members="{ item }">
        <div class="d-flex flex-wrap ga-1">
          <v-chip
              v-for="member in item.members"
              :key="member.server_id"
              size="x-small"
              variant="tonal"
          >
            {{ serverById.get(member.server_id)?.name || member.server_id }}
            <strong class="ml-1 text-primary">w{{ member.weight }}</strong>
          </v-chip>
          <span v-if="!item.members.length" class="text-caption text-medium-emphasis">—</span>
        </div>
      </template>

      <template #item.actions="{ item }">
        <v-btn color="error" variant="text" size="small" @click.stop="removePool(item.id)">
          Удалить
        </v-btn>
      </template>
    </v-data-table>

    <PoolModal
        v-model="showEditor"
        :pool="selectedPool"
        :servers="servers"
        @saved="load"
    />
  </v-container>
</template>

<style scoped>
.pools-page { padding: 24px; }
.pools-table :deep(tbody tr) { cursor: pointer; }
.pools-table :deep(tbody tr:hover) { background: rgba(43, 184, 148, .07) !important; }
.pool-name-col { font-weight: 600; font-size: 15px; }
</style>