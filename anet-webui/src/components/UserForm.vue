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
    <v-text-field v-model="user.uid" label="UID" variant="outlined" class="mb-3" />

    <!-- Балансируемые pools -->
    <v-select
        v-model="user.pool_ids"
        multiple
        item-title="label"
        item-value="value"
        :items="poolOptions"
        label="Балансируемые pools"
        placeholder="Выберите pools для этого пользователя"
        variant="outlined"
        class="mb-3"
    />

    <!-- Route map -->
    <v-select
        v-model="user.route_map_id"
        clearable
        item-title="label"
        item-value="value"
        :items="routeMapOptions"
        label="Route map"
        placeholder="Политика маршрутизации"
        variant="outlined"
        class="mb-3"
    />

    <!-- Active (editable) -->
    <v-switch v-model="user.is_active" label="Active" color="success" class="mb-2" />

    <!-- Static IP (editable) -->
    <v-text-field v-model="user.static_ip" label="Static IP" placeholder="e.g. 10.0.0.10" variant="outlined" class="mb-3" />

    <!-- ВЫБОР СЕРВЕРОВ (Many-to-Many) -->
    <v-select
        v-model="user.server_ids"
        multiple
        item-title="label"
        item-value="value"
        :items="serverOptions"
        label="Привязанные сервера (Локации)"
        placeholder="Выберите сервера для этого пользователя"
        variant="outlined"
        class="mb-3"
    />

    <v-divider class="my-4" />

    <!-- Readonly fields -->
    <v-text-field :modelValue="user.fingerprint" label="Fingerprint" disabled variant="outlined" class="mb-3" />
    <v-text-field :modelValue="user.created_at" label="Created At" disabled variant="outlined" class="mb-3" />
  </v-form>
</template>
