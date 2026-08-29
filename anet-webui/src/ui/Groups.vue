<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router' // <-- Импортируем роутер для переходов
import { GetGroups, DeleteGroup } from '@/api/groups'
import type { UserGroup } from '@/models/group'
import GroupModal from '@/components/GroupModal.vue'
import EntityCard from '@/components/EntityCard.vue'
import { useAppMessage } from '@/composables/useAppMessage'

const router = useRouter() // <-- Инициализируем роутер
const groups = ref<UserGroup[]>([])
const loading = ref(false)
const showEditor = ref(false)
const message = useAppMessage()

const formatBytes = (bytes: number | null | undefined) => {
  if (!bytes) return 'Без лимита трафика'
  const gb = bytes / (1024 * 1024 * 1024)
  return `${gb.toFixed(0)} ГБ`
}

const formatSpeed = (kbps: number | null | undefined) => {
  if (!kbps) return 'Без лимита скорости'
  const mbps = kbps / 1024
  return `${mbps.toFixed(0)} Мбит/с`
}

const formatSessions = (sessions: number | null | undefined) => {
  if (!sessions) return 'Безлимитные сессии'
  return `Сессий: ${sessions}`
}

const formatDuration = (days: number | null | undefined) => {
  if (!days) return 'Бессрочный доступ'
  return `Доступ при активации: +${days} дней`
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

// Открываем облегченную модалку создания новой группы
const openCreate = () => {
  showEditor.value = true
}

// Переход на выделенный полноэкранный интерфейс деталки
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
  <v-container max-width="1200" class="groups-page">
    <div class="d-flex justify-space-between align-center mb-5">
      <div>
        <h2 class="text-h6 font-weight-bold ma-0">Группы пользователей</h2>
        <span class="text-caption text-medium-emphasis">Группы пользователей и автоматические ограничения ресурсов</span>
      </div>
      <v-btn color="primary" @click="openCreate">Создать группу</v-btn>
    </div>

    <div class="position-relative">
      <v-row v-if="groups && groups.length > 0">
        <v-col v-for="group in groups" :key="group.id" cols="12" md="6" lg="4">
          <!-- Клик теперь вызывает переход на деталку вместо модалки редактирования -->
          <EntityCard
              :title="group.name"
              :subtitle="formatDuration(group.duration_days)"
              @click="goToDetail(group.id)"
          >
            <template #badges>
              <v-chip size="small" variant="outlined" :color="!group.sessions_limit ? 'info' : 'default'">
                {{ formatSessions(group.sessions_limit) }}
              </v-chip>
            </template>

            <template #meta>
              <v-chip color="primary" size="small" variant="tonal">
                Участников: {{ group.user_count }}
              </v-chip>
              <v-btn color="error" variant="text" size="small" @click.stop="remove(group.id)">
                Удалить
              </v-btn>
            </template>

            <template #footer>
              <v-chip size="small" variant="tonal" :color="!group.traffic_limit ? 'info' : 'success'">
                {{ formatBytes(group.traffic_limit) }}
              </v-chip>
              <v-chip size="small" variant="tonal" :color="!group.speed_limit ? 'info' : 'success'">
                {{ formatSpeed(group.speed_limit) }}
              </v-chip>
            </template>
          </EntityCard>
        </v-col>
      </v-row>

      <v-sheet v-else color="transparent" class="d-flex flex-column align-center justify-center pa-10 text-center mt-10">
        <v-icon icon="mdi-wallet-membership" size="64" color="medium-emphasis" class="mb-4" />
        <h3 class="text-h6 font-weight-bold mb-1">Группы пользователей ещё не созданы</h3>
        <p class="text-caption text-medium-emphasis">Создайте первую группу для автоматического назначения ограничений.</p>
      </v-sheet>
    </div>

    <!-- Модалка только для быстрого создания пустой группы -->
    <GroupModal
        v-model="showEditor"
        :group="null"
        @saved="load"
    />
  </v-container>
</template>

<style scoped>
.groups-page { padding: 24px; }
</style>

