<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { GetGroups, DeleteGroup } from '@/api/groups'
import type { UserGroup } from '@/models/group'
import GroupModal from '@/components/GroupModal.vue'
import { useAppMessage } from '@/composables/useAppMessage'

const router = useRouter()
const groups = ref<UserGroup[]>([])
const loading = ref(false)
const showEditor = ref(false)
const searchQuery = ref('')
const message = useAppMessage()

const headers = [
  { title: 'Группа', key: 'name', sortable: true },
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
    const res = await GetGroups()
    groups.value = res || []
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
  <v-container max-width="1400" class="groups-page">
      <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-6">
        <v-list-item
            class="px-0"
            subtitle="Группы пользователей и автоматические ограничения ресурсов"
        >
          <template #title>
            <h1 class="text-h5 font-weight-bold">Группы пользователей</h1>
          </template>
        </v-list-item>

        <div class="d-flex align-center ga-3">
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
        <v-btn color="primary" @click="openCreate">Создать группу</v-btn>
      </div>
    </div>

    <v-data-table
        :headers="headers"
        :items="groups"
        :search="searchQuery"
        :loading="loading"
        :items-per-page="10"
        :items-per-page-options="[10, 20, 50]"
        items-per-page-text="Строк на странице"
        loading-text="Загрузка групп пользователей…"
        no-data-text="Групп пока нет — создайте первую!"
        density="comfortable"
        class="groups-table border rounded-lg"
        hover
        @click:row="(_: unknown, data: { item: UserGroup }) => goToDetail(data.item.id)"
    >
      <template #item.name="{ item }">
        <span class="group-name-col">{{ item.name }}</span>
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
        <span>{{ formatDuration(item.duration_days) }}</span>
      </template>

      <template #item.user_count="{ item }">
        <v-chip color="primary" size="small" variant="tonal">
          Участников: {{ item.user_count }}
        </v-chip>
      </template>

      <template #item.actions="{ item }">
        <v-btn color="error" variant="text" size="small" @click.stop="remove(item.id)">
          Удалить
        </v-btn>
      </template>
    </v-data-table>

    <GroupModal
        v-model="showEditor"
        @saved="load"
    />
  </v-container>
</template>

<style scoped>
.groups-page { padding: 24px; }
.groups-table :deep(tbody tr) { cursor: pointer; }
.groups-table :deep(tbody tr:hover) { background: rgba(43, 184, 148, .07) !important; }
.group-name-col { font-weight: 600; font-size: 15px; }
</style>
