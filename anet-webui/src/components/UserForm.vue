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
    label: `${s.name} (${s.address})`,
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
  <n-form>
    <!-- UID (editable) -->
    <n-form-item label="UID">
      <n-input v-model:value="user.uid" />
    </n-form-item>

    <n-form-item label="Балансируемые pools">
      <n-select
          v-model:value="user.pool_ids"
          multiple
          :options="poolOptions"
          placeholder="Выберите pools для этого пользователя"
      />
    </n-form-item>

    <n-form-item label="Route map">
      <n-select
          v-model:value="user.route_map_id"
          clearable
          :options="routeMapOptions"
          placeholder="Политика маршрутизации"
      />
    </n-form-item>

    <!-- Active (editable) -->
    <n-form-item label="Active">
      <n-switch v-model:value="user.is_active" />
    </n-form-item>

    <!-- Static IP (editable) -->
    <n-form-item label="Static IP">
      <n-input v-model:value="user.static_ip" placeholder="e.g. 10.0.0.10" />
    </n-form-item>

    <!-- ВЫБОР СЕРВЕРОВ (Many-to-Many) -->
    <n-form-item label="Привязанные сервера (Локации)">
      <n-select
          v-model:value="user.server_ids"
          multiple
          :options="serverOptions"
          placeholder="Выберите сервера для этого пользователя"
      />
    </n-form-item>

    <n-divider />

    <!-- Readonly fields -->
    <n-form-item label="Fingerprint">
      <n-input :value="user.fingerprint" disabled />
    </n-form-item>

    <n-form-item label="Created At">
      <n-input :value="user.created_at" disabled />
    </n-form-item>
  </n-form>
</template>
