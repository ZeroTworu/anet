<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { CreateUser } from '@/api/users'
import { GetServers } from '@/api/servers'
import { GetPools } from '@/api/pools'
import type { CreateUserRequest } from '@/models/user'
import type { Server } from '@/models/server'
import type { NodePool } from '@/models/pool'
import { GetRouteMaps } from '@/api/route-maps'
import type { RouteMap } from '@/models/route-map'
import { formatDate } from '@/utils'

const show = defineModel<boolean>('show')

const emit = defineEmits<{
  (e: 'created'): void
}>()

const rateEnabled = ref(false)
const availableServers = ref<Server[]>([])
const availablePools = ref<NodePool[]>([])
const availableRouteMaps = ref<RouteMap[]>([])

const rateForm = ref({
  sessions: 0,
  date_end: formatDate(new Date(), 'yyyy-MM-dd-HH:mm'),
})

const form = ref({
  uid: '',
  server_ids: [] as string[], // Новое поле массива серверов
  pool_ids: [] as string[],
  route_map_id: null as string | null,
})

const loading = ref(false)

const loadServers = async () => {
  try {
    availableServers.value = await GetServers()
  } catch (e) {
    console.error(e)
  }
}

const serverOptions = computed(() => {
  return availableServers.value.map(s => ({
    label: `${s.name} (${s.address})`,
    value: s.id,
  }))
})
const poolOptions = computed(() => availablePools.value.filter(pool => pool.is_active).map(pool => ({
  label: `${pool.name} · ${pool.strategy}`,
  value: pool.id,
})))
const routeMapOptions = computed(() => availableRouteMaps.value.filter(map => map.is_active).map(map => ({
  label: `${map.name} · rev ${map.revision}`,
  value: map.id,
})))

onMounted(async () => {
  await Promise.all([
    loadServers(),
    GetPools().then(pools => { availablePools.value = pools }),
    GetRouteMaps().then(maps => { availableRouteMaps.value = maps }),
  ])
})

const create = async () => {
  loading.value = true
  try {
    const payload: CreateUserRequest = {
      uid: form.value.uid,
      server_ids: form.value.server_ids, // <--- Улетает массив привязки при создании!
      pool_ids: form.value.pool_ids,
      route_map_id: form.value.route_map_id,
      rate: rateEnabled.value
          ? {
            sessions: rateForm.value.sessions,
            date_end: rateForm.value.date_end,
          }
          : null,
    }

    await CreateUser(payload)
    emit('created')
    show.value = false

    form.value = { uid: '', server_ids: [], pool_ids: [], route_map_id: null }
    rateEnabled.value = false
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <n-modal v-model:show="show" preset="card" style="width: 600px">
    <n-form>
      <n-form-item label="UID">
        <n-input v-model:value="form.uid" placeholder="e.g. Koshka_Vasya" />
      </n-form-item>

      <n-form-item label="Привязать к pools">
        <n-select
            v-model:value="form.pool_ids"
            multiple
            :options="poolOptions"
            placeholder="Выберите балансируемые группы"
        />
      </n-form-item>

      <n-form-item label="Route map">
        <n-select
            v-model:value="form.route_map_id"
            clearable
            :options="routeMapOptions"
            placeholder="Политика маршрутизации"
        />
      </n-form-item>

      <!-- ПРИВЯЗКА К СЕРВЕРАМ НА СТАРТЕ -->
      <n-form-item label="Привязать к серверам">
        <n-select
            v-model:value="form.server_ids"
            multiple
            :options="serverOptions"
            placeholder="Выберите локации"
        />
      </n-form-item>

      <n-form-item>
        <n-checkbox v-model:checked="rateEnabled"> Create rate </n-checkbox>
      </n-form-item>

      <div v-if="rateEnabled">
        <n-form-item label="Sessions">
          <n-input-number v-model:value="rateForm.sessions" />
        </n-form-item>

        <n-form-item label="Date End">
          <n-date-picker
              v-model:formatted-value="rateForm.date_end"
              type="datetime"
              value-format="yyyy-MM-dd-HH:mm"
          />
        </n-form-item>
      </div>
    </n-form>
    <template #footer>
      <n-space justify="end">
        <n-button @click="show = false">Cancel</n-button>
        <n-button type="primary" :loading="loading" @click="create"> Create </n-button>
      </n-space>
    </template>
  </n-modal>
</template>
