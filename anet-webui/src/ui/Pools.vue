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

const showEditor = ref(false)
const selectedPool = ref<NodePool | null>(null)

const serverById = computed(() => new Map(servers.value.map(server => [server.id, server])))

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
  <main class="pools-page">
    <div class="d-flex justify-space-between align-center page-title">
      <div>
        <h2>Node Pools</h2>
        <span>Группы узлов и стратегия выбора entry point</span>
      </div>
      <v-btn color="primary" @click="openCreate">Создать pool</v-btn>
    </div>

    <div class="position-relative">
      <v-row v-if="pools.length > 0">
        <v-col v-for="pool in pools" :key="pool.id" cols="12" md="6" lg="4">
          <v-card hover class="pa-4 h-100 cursor-pointer d-flex flex-column" @click="openEdit(pool)">
            <div class="d-flex justify-space-between align-start mb-4">
              <div>
                <div class="d-flex align-center gap-2 mb-1">
                  <strong class="text-h6">{{ pool.name }}</strong>
                  <v-chip :color="pool.is_active ? 'success' : 'default'" size="small">
                    {{ pool.is_active ? 'ACTIVE' : 'DISABLED' }}
                  </v-chip>
                </div>
                <div class="text-medium-emphasis text-body-2">
                  {{ pool.strategy === 'weighted' ? 'Weighted rendezvous' : 'Least connections' }}
                </div>
              </div>
              <div class="d-flex flex-column align-end">
                <span class="text-caption text-medium-emphasis mb-2">
                  Nodes: {{ pool.members.length }}
                </span>
                <v-btn color="error" variant="text" size="small" @click.stop="removePool(pool.id)">
                  Удалить
                </v-btn>
              </div>
            </div>

            <v-spacer></v-spacer>

            <div class="d-flex flex-wrap gap-2 mt-auto pt-2 border-t">
              <v-chip
                  v-for="member in pool.members"
                  :key="member.server_id"
                  size="small"
                  variant="tonal"
              >
                {{ serverById.get(member.server_id)?.name || member.server_id }} · w{{ member.weight }}
              </v-chip>
            </div>
          </v-card>
        </v-col>
      </v-row>

      <v-empty-state
          v-else
          title="Pools ещё не созданы"
          text="Создайте первую группу узлов для распределения трафика."
          class="mt-10"
      />
    </div>

    <PoolModal
        v-model="showEditor"
        :pool="selectedPool"
        :servers="servers"
        @saved="load"
    />
  </main>
</template>

<style scoped>
.pools-page { max-width: 1200px; margin: 0 auto; padding: 24px; }
.page-title { margin-bottom: 24px; }
.page-title h2 { margin: 0 0 4px; font-weight: 600; font-size: 20px; }
.page-title span { color: #94a3b8; font-size: 13px; }
.gap-2 { gap: 8px; }
.border-t { border-top: 1px solid rgba(128, 128, 128, 0.2); }
</style>
