<script setup lang="ts">
// Здесь администратор задаёт состав пула и алгоритм выбора entry point.
// Веса применяются weighted rendezvous, а least-connections использует
// active_connections из последнего heartbeat ноды.
import { computed, onMounted, ref } from 'vue'
import { CreatePool, DeletePool, GetPools, UpdatePool } from '@/api/pools'
import { GetServers } from '@/api/servers'
import type { NodePool, SaveNodePoolRequest } from '@/models/pool'
import type { Server } from '@/models/server'

const pools = ref<NodePool[]>([])
const servers = ref<Server[]>([])
const loading = ref(false)
const saving = ref(false)
const showEditor = ref(false)
const editingId = ref<string | null>(null)
const form = ref<SaveNodePoolRequest>({
  name: '', strategy: 'weighted', is_active: true, members: [],
})

const strategyOptions = [
  { label: 'Weighted rendezvous', value: 'weighted' },
  { label: 'Least connections', value: 'least_connections' },
]
const selectedIds = computed(() => new Set(form.value.members.map(member => member.server_id)))
const availableServers = computed(() => servers.value.filter(server => !selectedIds.value.has(server.id)))
const serverById = computed(() => new Map(servers.value.map(server => [server.id, server])))

const load = async () => {
  loading.value = true
  try {
    ;[pools.value, servers.value] = await Promise.all([GetPools(), GetServers()])
  } finally {
    loading.value = false
  }
}

const openCreate = () => {
  editingId.value = null
  form.value = { name: '', strategy: 'weighted', is_active: true, members: [] }
  showEditor.value = true
}

const openEdit = (pool: NodePool) => {
  editingId.value = pool.id
  form.value = {
    name: pool.name,
    strategy: pool.strategy,
    is_active: pool.is_active,
    members: pool.members.map(member => ({ ...member })),
  }
  showEditor.value = true
}

const addNode = (serverId: string) => {
  form.value.members.push({ server_id: serverId, weight: 1 })
}

const save = async () => {
  saving.value = true
  try {
    if (editingId.value) await UpdatePool(editingId.value, form.value)
    else await CreatePool(form.value)
    showEditor.value = false
    await load()
  } finally {
    saving.value = false
  }
}

const removePool = async (id: string) => {
  await DeletePool(id)
  await load()
}

onMounted(load)
</script>

<template>
  <main class="pools-page">
    <div justify="space-between" align="center" class="page-title">
      <div><h2>Node Pools</h2><span>Группы узлов и стратегия выбора entry point</span></div>
      <v-btn color="primary" @click="openCreate">Создать pool</v-btn>
    </div>

    <div class="position-relative">
      <v-row :cols="1" :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
        <v-col v-for="pool in pools" :key="pool.id">
          <v-card hoverable @click="openEdit(pool)">
            <div justify="space-between" align="start">
              <div>
                <div align="center">
                  <strong>{{ pool.name }}</strong>
                  <v-chip  :color="pool.is_active ? 'success' : 'default'" size="small">{{ pool.is_active ? 'ACTIVE' : 'DISABLED' }}</v-chip>
                </div>
                <div class="strategy">{{ pool.strategy === 'weighted' ? 'Weighted rendezvous' : 'Least connections' }}</div>
              </div>
              <div align="center">
                <div label="Nodes" :modelValue="pool.members.length" />
                <div>
                  <v-btn color="error" text @click.stop>Удалить</v-btn>
                  Удалить pool и назначения пользователей?
                </div>
              </div>
            </div>
            <div class="members">
              <v-chip v-for="member in pool.members" :key="member.server_id" size="small">
                {{ serverById.get(member.server_id)?.name || member.server_id }} · w{{ member.weight }}
              </v-chip>
            </div>
          </v-card>
        </v-col>
      </v-row>
      <v-empty-state v-if="pools.length === 0" description="Pools ещё не созданы" />
    </div>

    <v-dialog v-model="showEditor" style="width: 720px" :title="editingId ? 'Редактировать pool' : 'Создать pool'">
      <v-form>
        <div label="Название"><v-text-field v-model="form.name" /></div>
        <div label="Стратегия"><v-select v-model="form.strategy" :items="strategyOptions" /></div>
        <div label="Активен"><v-switch v-model="form.is_active" /></div>
        <v-divider>Узлы</v-divider>
        <div vertical style="width: 100%">
          <div v-for="(member, index) in form.members" :key="member.server_id" align="center" justify="space-between">
            <span>{{ serverById.get(member.server_id)?.name || member.server_id }}</span>
            <div align="center">
              <span class="weight-label">Вес</span>
              <v-number-input v-model="member.weight" :min="1" :max="10000" style="width: 110px" />
              <v-btn text color="error" @click="form.members.splice(index, 1)">Убрать</v-btn>
            </div>
          </div>
          <v-select
              v-if="availableServers.length"
              :modelValue="null"
              :items="availableServers.map(server => ({ title: `${server.name} (${server.dsn})`, value: server.id }))"
              placeholder="Добавить узел"
              @update:modelValue="value => value && addNode(String(value))"
          />
        </div>
      </v-form>
      <div class="d-flex justify-end ga-4">
        <div justify="end">
          <v-btn @click="showEditor = false">Отмена</v-btn>
          <v-btn color="primary" :loading="saving" :disabled="!form.name.trim()" @click="save">Сохранить</v-btn>
        </div>
      </div>
    </v-dialog>
  </main>
</template>

<style scoped>
.pools-page { max-width: 1200px; margin: 0 auto; padding: 24px; }
.page-title { margin-bottom: 24px; }
.page-title h2 { margin: 0 0 4px; font-size: 22px; }
.page-title span, .strategy { color: #94a3b8; font-size: 13px; }
.strategy { margin-top: 7px; }
.members { margin-top: 18px; }
.weight-label { color: #94a3b8; font-size: 12px; }
</style>
