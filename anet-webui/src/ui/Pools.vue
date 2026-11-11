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
  <v-container fluid class="pools-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-4">
      <v-list-item
        class="px-0"
        subtitle="Группы узлов и стратегии выбора entry point (Weighted rendezvous / Least connections)"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">Node Pools (Пулы серверов)</h1>
        </template>
      </v-list-item>
    </div>

    <div class="d-flex justify-space-between align-center mb-4">
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
      <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreate">
        + ДОБАВИТЬ ПУЛ
      </v-btn>
    </div>

    <v-data-table
      :headers="headers"
      :items="pools"
      :search="searchQuery"
      :loading="loading"
      :items-per-page="10"
      :items-per-page-options="[10, 20, 50]"
      items-per-page-text="Items per page:"
      loading-text="Загрузка пулов балансировки…"
      no-data-text="Пулов пока нет — создайте первый!"
      density="comfortable"
      class="border rounded-lg"
      hover
      @click:row="(_: unknown, data: { item: NodePool }) => openEdit(data.item)"
    >
      <template #item.name="{ item }">
        <span class="font-weight-bold">{{ item.name }}</span>
      </template>

      <template #item.strategy="{ item }">
        <v-chip size="small" variant="outlined">
          {{ item.strategy === 'weighted' ? 'Weighted rendezvous' : 'Least connections' }}
        </v-chip>
      </template>

      <template #item.is_active="{ item }">
        <v-chip :color="item.is_active ? 'success' : 'default'" size="small">
          {{ item.is_active ? 'ACTIVE' : 'OFF' }}
        </v-chip>
      </template>

      <template #item.members="{ item }">
        <div class="d-flex flex-wrap ga-1">
          <v-chip
            v-for="(member, idx) in item.members"
            :key="`${member.server_id}-${idx}`"
            size="small"
            variant="tonal"
            color="secondary"
          >
            {{ serverById.get(member.server_id)?.name || member.server_id }}
            <span v-if="member.protocol" class="ml-1 font-weight-bold text-uppercase">[{{ member.protocol }}<template v-if="member.wrtc_mode">: {{ member.wrtc_mode }}</template>]</span>
            <span v-if="member.port_or_url" class="ml-1 text-medium-emphasis">({{ member.port_or_url }})</span>
            <strong class="ml-1 text-primary">w{{ member.weight }}</strong>
          </v-chip>
          <span v-if="!item.members.length" class="text-caption text-medium-emphasis">—</span>
        </div>
      </template>

      <template #item.actions="{ item }">
        <div class="d-flex ga-1 justify-center flex-nowrap" @click.stop>
          <v-btn
            icon="mdi-pencil"
            size="small"
            variant="text"
            title="Редактировать пул"
            @click="openEdit(item)"
          />
          <v-btn
            icon="mdi-delete"
            size="small"
            variant="text"
            color="error"
            title="Удалить пул"
            @click="removePool(item.id)"
          />
        </div>
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
.pools-page {
  padding: 24px;
}
</style>