<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { GetGroups, DeleteGroup } from '@/api/groups'
import { GetPools } from '@/api/pools'
import type { UserGroup } from '@/models/group'
import type { NodePool } from '@/models/pool'
import GroupModal from '@/components/GroupModal.vue'
import { useAppMessage } from '@/composables/useAppMessage'

const router = useRouter()
const groups = ref<UserGroup[]>([])
const pools = ref<NodePool[]>([])
const loading = ref(false)
const showEditor = ref(false)
const searchQuery = ref('')
const message = useAppMessage()

const poolById = computed(() => new Map(pools.value.map(p => [p.id, p])))

const headers = [
  { title: 'Группа', key: 'name', sortable: true },
  { title: 'Группы серверов', key: 'pool_ids', sortable: false },
  { title: 'Ограничение трафика', key: 'traffic_limit', sortable: true },
  { title: 'Ограничение скорости', key: 'speed_limit', sortable: true },
  { title: 'Сессий', key: 'sessions_limit', sortable: true, align: 'center' as const },
  { title: 'Период подписки', key: 'duration_days', sortable: true },
  { title: 'Участники', key: 'user_count', sortable: true, align: 'center' as const },
  { title: 'Действия', key: 'actions', sortable: false, align: 'center' as const },
]

const formatBytes = (bytes: number | null | undefined) => {
  if (!bytes) return 'Безлимит'
  const gb = bytes / (1024 * 1024 * 1024)
  return `${gb.toFixed(0)} ГБ`
}

const formatSpeed = (kbps: number | null | undefined) => {
  if (!kbps) return 'Безлимит'
  const mbps = kbps / 1024
  return `${mbps.toFixed(0)} Мбит/с`
}

const formatSessions = (sessions: number | null | undefined) => {
  if (!sessions) return 'Безлимит'
  return `${sessions}`
}

const formatDuration = (days: number | null | undefined) => {
  if (!days) return 'Бессрочный доступ'
  return `+${days} дней`
}

const load = async () => {
  loading.value = true
  try {
    const [resGroups, resPools] = await Promise.all([
      GetGroups(),
      GetPools().catch(() => [] as NodePool[]),
    ])
    groups.value = resGroups || []
    pools.value = resPools || []
  } catch (err) {
    message.error('Не удалось загрузить группы пользователей')
  } finally {
    loading.value = false
  }
}

const openCreate = () => {
  showEditor.value = true
}

const goToDetail = (id: string) => {
  router.push(`/groups/${id}`)
}

const remove = async (id: string) => {
  if (!confirm('Вы уверены, что хотите удалить эту группу пользователей? У всех ее участников сбросится группа.')) return
  try {
    await DeleteGroup(id)
    message.success('Группа удалена')
    await load()
  } catch (e: any) {
    message.error(e?.response?.data || 'Не удалось удалить группу пользователей')
  }
}

onMounted(() => {
  load()
})
</script>

<template>
  <v-container fluid class="groups-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-4">
      <v-list-item
        class="px-0"
        subtitle="Группы пользователей и автоматические ограничения ресурсов"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">User Groups (Группы пользователей)</h1>
        </template>
      </v-list-item>
    </div>

    <div class="d-flex justify-space-between align-center mb-4">
      <v-text-field
        v-model="searchQuery"
        prepend-inner-icon="mdi-magnify"
        label="Поиск по группам..."
        variant="outlined"
        density="compact"
        hide-details
        single-line
        style="width: 280px"
      />
      <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreate">
        + ДОБАВИТЬ ГРУППУ
      </v-btn>
    </div>

    <v-data-table
      :headers="headers"
      :items="groups"
      :search="searchQuery"
      :loading="loading"
      :items-per-page="10"
      :items-per-page-options="[10, 20, 50]"
      items-per-page-text="Items per page:"
      loading-text="Загрузка групп пользователей…"
      no-data-text="Групп пока нет — создайте первую!"
      density="comfortable"
      class="border rounded-lg"
      hover
      @click:row="(_: unknown, data: { item: UserGroup }) => goToDetail(data.item.id)"
    >
      <template #item.name="{ item }">
        <span class="font-weight-bold">{{ item.name }}</span>
      </template>

      <template #item.pool_ids="{ item }">
        <div class="d-flex flex-wrap ga-1">
          <v-chip
            v-for="pId in (item.pool_ids || [])"
            :key="pId"
            size="small"
            variant="tonal"
            color="primary"
          >
            {{ poolById.get(pId)?.name || pId }}
          </v-chip>
          <span v-if="!item.pool_ids?.length" class="text-caption text-medium-emphasis">Все (стандартно)</span>
        </div>
      </template>

      <template #item.traffic_limit="{ item }">
        <v-chip size="small" variant="tonal" :color="!item.traffic_limit ? 'info' : 'success'">
          {{ formatBytes(item.traffic_limit) }}
        </v-chip>
      </template>

      <template #item.speed_limit="{ item }">
        <v-chip size="small" variant="tonal" :color="!item.speed_limit ? 'info' : 'success'">
          {{ formatSpeed(item.speed_limit) }}
        </v-chip>
      </template>

      <template #item.sessions_limit="{ item }">
        <v-chip size="small" variant="outlined" :color="!item.sessions_limit ? 'info' : 'default'">
          {{ formatSessions(item.sessions_limit) }}
        </v-chip>
      </template>

      <template #item.duration_days="{ item }">
        <span class="text-caption text-medium-emphasis">{{ formatDuration(item.duration_days) }}</span>
      </template>

      <template #item.user_count="{ item }">
        <v-chip color="primary" size="small" variant="tonal" prepend-icon="mdi-account-multiple">
          {{ item.user_count }}
        </v-chip>
      </template>

      <template #item.actions="{ item }">
        <div class="d-flex ga-1 justify-center flex-nowrap" @click.stop>
          <v-btn
            icon="mdi-pencil"
            size="small"
            variant="text"
            title="Параметры группы"
            @click="goToDetail(item.id)"
          />
          <v-btn
            icon="mdi-delete"
            size="small"
            variant="text"
            color="error"
            title="Удалить группу"
            @click="remove(item.id)"
          />
        </div>
      </template>
    </v-data-table>

    <GroupModal
      v-model="showEditor"
      @saved="load"
    />
  </v-container>
</template>

<style scoped>
.groups-page {
  padding: 24px;
}
</style>
