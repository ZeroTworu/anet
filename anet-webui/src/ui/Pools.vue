<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { DeletePool, GetPools } from '@/api/pools'
import { GetServers } from '@/api/servers'
import type { NodePool } from '@/models/pool'
import type { Server } from '@/models/server'
import PoolModal from '@/components/PoolModal.vue'
import EntityCard from '@/components/EntityCard.vue'

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
  <v-container max-width="1200" class="pools-page">
    <div class="d-flex justify-space-between align-center mb-5">
      <div>
        <h2 class="text-h6 font-weight-bold ma-0">Node Pools</h2>
        <span class="text-caption text-medium-emphasis">Группы узлов и стратегия выбора entry point</span>
      </div>
      <v-btn color="primary" @click="openCreate">Создать pool</v-btn>
    </div>

    <div class="position-relative">
      <v-row v-if="pools.length > 0">
        <v-col v-for="pool in pools" :key="pool.id" cols="12" md="6" lg="4">
          <EntityCard
              :title="pool.name"
              :subtitle="pool.strategy === 'weighted' ? 'Weighted rendezvous' : 'Least connections'"
              @click="openEdit(pool)"
          >
            <template #badges>
              <v-chip :color="pool.is_active ? 'success' : 'default'" size="small">
                {{ pool.is_active ? 'ACTIVE' : 'DISABLED' }}
              </v-chip>
            </template>

            <template #meta>
              <span class="text-caption text-medium-emphasis">Nodes: {{ pool.members.length }}</span>
              <v-btn color="error" variant="text" size="small" @click.stop="removePool(pool.id)">
                Удалить
              </v-btn>
            </template>

            <template #footer>
              <v-chip
                  v-for="member in pool.members"
                  :key="member.server_id"
                  size="small"
                  variant="tonal"
              >
                {{ serverById.get(member.server_id)?.name || member.server_id }} · w{{ member.weight }}
              </v-chip>
            </template>
          </EntityCard>
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
  </v-container>
</template>

<style scoped>
.pools-page { padding: 24px; }
</style>
