<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import type { User } from '@/models/user'
import { GetServers } from '@/api/servers'
import type { Server } from '@/models/server'
import { GetPools } from '@/api/pools'
import type { NodePool } from '@/models/pool'
import { GetRouteMaps } from '@/api/route-maps'
import type { RouteMap } from '@/models/route-map'

const user = defineModel<User>('modelValue', {
  required: true,
})

const availableServers = ref<Server[]>([])
const availablePools = ref<NodePool[]>([])
const availableRouteMaps = ref<RouteMap[]>([])

// Форматируем список серверов под опции n-select
const serverOptions = computed(() => {
  return availableServers.value.map(s => ({
    label: `${s.name} (${s.dsn})`,
    value: s.id,
  }))
})
const poolOptions = computed(() => availablePools.value.map(pool => ({
  label: `${pool.name} · ${pool.strategy}`,
  value: pool.id,
})))
const routeMapOptions = computed(() => availableRouteMaps.value.map(map => ({
  label: `${map.name} · rev ${map.revision}`,
  value: map.id,
})))

onMounted(async () => {
  try {
    // Загружаем список серверов строго в момент монтирования формы
    ;[availableServers.value, availablePools.value, availableRouteMaps.value] = await Promise.all([
      GetServers(), GetPools(), GetRouteMaps(),
    ])

    // Защита: гарантируем, что server_ids инициализирован как массив
    if (!user.value.server_ids) {
      user.value.server_ids = []
    }
    if (!user.value.pool_ids) user.value.pool_ids = []
  } catch (e) {
    console.error("Failed to fetch servers inside form:", e)
  }
})
</script>

<template>
  <v-form>
    <!-- UID (editable) -->
    <div label="UID">
      <v-text-field v-model="user.uid" />
    </div>

    <div label="Балансируемые pools">
      <v-select
          v-model="user.pool_ids"
          multiple
          :items="poolOptions"
          placeholder="Выберите pools для этого пользователя"
      />
    </div>

    <div label="Route map">
      <v-select
          v-model="user.route_map_id"
          clearable
          :items="routeMapOptions"
          placeholder="Политика маршрутизации"
      />
    </div>

    <!-- Active (editable) -->
    <div label="Active">
      <v-switch v-model="user.is_active" />
    </div>

    <!-- Static IP (editable) -->
    <div label="Static IP">
      <v-text-field v-model="user.static_ip" placeholder="e.g. 10.0.0.10" />
    </div>

    <!-- ВЫБОР СЕРВЕРОВ (Many-to-Many) -->
    <div label="Привязанные сервера (Локации)">
      <v-select
          v-model="user.server_ids"
          multiple
          :items="serverOptions"
          placeholder="Выберите сервера для этого пользователя"
      />
    </div>

    <v-divider />

    <!-- Readonly fields -->
    <div label="Fingerprint">
      <v-text-field :modelValue="user.fingerprint" disabled />
    </div>

    <div label="Created At">
      <v-text-field :modelValue="user.created_at" disabled />
    </div>
  </v-form>
</template>
