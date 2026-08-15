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
    <n-space justify="space-between" align="center" class="page-title">
      <div><h2>Node Pools</h2><span>Группы узлов и стратегия выбора entry point</span></div>
      <n-button type="primary" @click="openCreate">Создать pool</n-button>
    </n-space>

    <n-spin :show="loading">
      <n-grid :cols="1" :x-gap="16" :y-gap="16" responsive="screen" item-responsive>
        <n-grid-item v-for="pool in pools" :key="pool.id">
          <n-card hoverable @click="openEdit(pool)">
            <n-space justify="space-between" align="start">
              <div>
                <n-space align="center">
                  <strong>{{ pool.name }}</strong>
                  <n-tag :type="pool.is_active ? 'success' : 'default'" size="small">{{ pool.is_active ? 'ACTIVE' : 'DISABLED' }}</n-tag>
                </n-space>
                <div class="strategy">{{ pool.strategy === 'weighted' ? 'Weighted rendezvous' : 'Least connections' }}</div>
              </div>
              <n-space align="center">
                <n-statistic label="Nodes" :value="pool.members.length" />
                <n-popconfirm @positive-click="removePool(pool.id)">
                  <template #trigger><n-button type="error" text @click.stop>Удалить</n-button></template>
                  Удалить pool и назначения пользователей?
                </n-popconfirm>
              </n-space>
            </n-space>
            <n-space class="members">
              <n-tag v-for="member in pool.members" :key="member.server_id" size="small">
                {{ serverById.get(member.server_id)?.name || member.server_id }} · w{{ member.weight }}
              </n-tag>
            </n-space>
          </n-card>
        </n-grid-item>
      </n-grid>
      <n-empty v-if="pools.length === 0" description="Pools ещё не созданы" />
    </n-spin>

    <n-modal v-model:show="showEditor" preset="card" style="width: 720px" :title="editingId ? 'Редактировать pool' : 'Создать pool'">
      <n-form>
        <n-form-item label="Название"><n-input v-model:value="form.name" /></n-form-item>
        <n-form-item label="Стратегия"><n-select v-model:value="form.strategy" :options="strategyOptions" /></n-form-item>
        <n-form-item label="Активен"><n-switch v-model:value="form.is_active" /></n-form-item>
        <n-divider>Узлы</n-divider>
        <n-space vertical style="width: 100%">
          <n-space v-for="(member, index) in form.members" :key="member.server_id" align="center" justify="space-between">
            <span>{{ serverById.get(member.server_id)?.name || member.server_id }}</span>
            <n-space align="center">
              <span class="weight-label">Вес</span>
              <n-input-number v-model:value="member.weight" :min="1" :max="10000" style="width: 110px" />
              <n-button text type="error" @click="form.members.splice(index, 1)">Убрать</n-button>
            </n-space>
          </n-space>
          <n-select
              v-if="availableServers.length"
              :value="null"
              :options="availableServers.map(server => ({ label: `${server.name} (${server.address})`, value: server.id }))"
              placeholder="Добавить узел"
              @update:value="addNode"
          />
        </n-space>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showEditor = false">Отмена</n-button>
          <n-button type="primary" :loading="saving" :disabled="!form.name.trim()" @click="save">Сохранить</n-button>
        </n-space>
      </template>
    </n-modal>
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
