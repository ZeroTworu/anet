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
    label: `${s.name} (${s.dsn})`,
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
  <v-dialog v-model="show" style="width: 600px">
    <v-form>
      <div label="UID">
        <v-text-field v-model="form.uid" placeholder="e.g. Koshka_Vasya" />
      </div>

      <div label="Привязать к pools">
        <v-select
            v-model="form.pool_ids"
            multiple
            :items="poolOptions"
            placeholder="Выберите балансируемые группы"
        />
      </div>

      <div label="Route map">
        <v-select
            v-model="form.route_map_id"
            clearable
            :items="routeMapOptions"
            placeholder="Политика маршрутизации"
        />
      </div>

      <!-- ПРИВЯЗКА К СЕРВЕРАМ НА СТАРТЕ -->
      <div label="Привязать к серверам">
        <v-select
            v-model="form.server_ids"
            multiple
            :items="serverOptions"
            placeholder="Выберите локации"
        />
      </div>

      <div>
        <v-checkbox v-model="rateEnabled"> Create rate </v-checkbox>
      </div>

      <div v-if="rateEnabled">
        <div label="Sessions">
          <v-number-input v-model="rateForm.sessions" />
        </div>

        <div label="Date End">
          <v-text-field
              v-model="rateForm.date_end"
              type="datetime-local"
              value-format="yyyy-MM-dd-HH:mm"
          />
        </div>
      </div>
    </v-form>
    <div class="d-flex justify-end ga-4">
      <div justify="end">
        <v-btn @click="show = false">Cancel</v-btn>
        <v-btn color="primary" :loading="loading" @click="create"> Create </v-btn>
      </div>
    </div>
  </v-dialog>
</template>
