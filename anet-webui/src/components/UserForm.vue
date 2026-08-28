<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import type { User } from '@/models/user'
import { GetServers } from '@/api/servers'
import type { Server } from '@/models/server'
import { GetPools } from '@/api/pools'
import type { NodePool } from '@/models/pool'
import { GetRouteMaps } from '@/api/route-maps'
import type { RouteMap } from '@/models/route-map'
import { GetGroups } from '@/api/groups'
import type { UserGroup } from '@/models/group'

const user = defineModel<User>('modelValue', {
  required: true,
})

// Валидность формы наружу (кнопка Create/Save в родительской модалке)
const valid = defineModel<boolean>('valid', { default: false })

// Режим создания: показываем только поля, входящие в CreateUserRequest
const props = defineProps<{
  creating?: boolean
}>()

const availableServers = ref<Server[]>([])
const availablePools = ref<NodePool[]>([])
const availableRouteMaps = ref<RouteMap[]>([])
const availableGroups = ref<UserGroup[]>([])

// Опции v-select в стандартном формате { title, value }
const serverOptions = computed(() => availableServers.value.map(s => ({
  title: `${s.name} (${s.address})`,
  value: s.id,
})))
const poolOptions = computed(() => availablePools.value.map(pool => ({
  title: `${pool.name} · ${pool.strategy}`,
  value: pool.id,
})))
const routeMapOptions = computed(() => availableRouteMaps.value.map(map => ({
  title: `${map.name} · rev ${map.revision}`,
  value: map.id,
})))
const groupOptions = computed(() => availableGroups.value.map(group => ({
  title: `${group.name} (+${group.duration_days} дн.)`,
  value: group.id,
})))

const uidRules = [
  (v: string) => !!v?.trim() || 'UID обязателен',
  (v: string) => /^[A-Za-z0-9_.-]{2,64}$/.test(v) || '2–64 символа: латиница, цифры, . _ -',
]

onMounted(async () => {
  try {
    // Загружаем справочники, включая новые Группы Пользователей
    ;[
      availableServers.value,
      availablePools.value,
      availableRouteMaps.value,
      availableGroups.value
    ] = await Promise.all([
      GetServers(),
      GetPools(),
      GetRouteMaps(),
      GetGroups(),
    ])

    // Защита: гарантируем, что массивы инициализированы
    if (!user.value.server_ids) user.value.server_ids = []
    if (!user.value.pool_ids) user.value.pool_ids = []
  } catch (e) {
    console.error('Failed to fetch dictionaries inside form:', e)
  }
})
</script>

<template>
  <v-form v-model="valid" @submit.prevent>
    <!-- UID (editable) -->
    <v-text-field v-model="user.uid" label="UID" :rules="uidRules" counter="64" class="mb-3" />

    <!-- Выбор группы (Тарифа) -->
    <v-select
        v-model="user.group_id"
        clearable
        :items="groupOptions"
        label="Группа пользователей"
        placeholder="Выберите группу пользователей"
        class="mb-3"
    />

    <!-- Балансируемые pools -->
    <v-select
        v-model="user.pool_ids"
        multiple
        :items="poolOptions"
        label="Балансируемые pools"
        placeholder="Выберите pools для этого пользователя"
        class="mb-3"
    />

    <!-- Route map -->
    <v-select
        v-model="user.route_map_id"
        clearable
        :items="routeMapOptions"
        label="Route map"
        placeholder="Политика маршрутизации"
        class="mb-3"
    />

    <template v-if="!props.creating">
      <!-- Active (editable) -->
      <v-switch v-model="user.is_active" label="Active" color="success" class="mb-2" />

      <!-- Static IP (editable) -->
      <v-text-field v-model="user.static_ip" label="Static IP" placeholder="e.g. 10.0.0.10" class="mb-3" />
    </template>

    <!-- ВЫБОР СЕРВЕРОВ (Many-to-Many) -->
    <v-select
        v-model="user.server_ids"
        multiple
        :items="serverOptions"
        label="Привязанные сервера (Локации)"
        placeholder="Выберите сервера для этого пользователя"
    />

    <template v-if="!props.creating">
      <v-divider class="my-4" />

      <!-- Readonly fields -->
      <v-text-field :model-value="user.fingerprint" label="Fingerprint" disabled class="mb-3" />
      <v-text-field :model-value="user.created_at" label="Created At" disabled />
    </template>
  </v-form>
</template>
