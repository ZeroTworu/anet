<script setup lang="ts">
import { onMounted, ref, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { GetGroup, UpdateGroup, GetGroupMembers, AddGroupMember, RemoveGroupMember } from '@/api/groups'
import { GetUsers } from '@/api/users'
import type { UserGroup, SaveGroupRequest } from '@/models/group'
import type { User } from '@/models/user'
import { useAppMessage } from '@/composables/useAppMessage'

const route = useRoute()
const router = useRouter()
const message = useAppMessage()

const groupId = String(route.params.id)

// Состояние загрузки
const loadingGroup = ref(false)
const savingGroup = ref(false)
const loadingMembers = ref(false)
const searchLoading = ref(false)

// Данные
const group = ref<UserGroup | null>(null)
const members = ref<User[]>([])
const totalMembers = ref(0)
const showAddModal = ref(false)
const autocompleteRef = ref<any>(null)

// Фильтры и пагинация таблицы участников
const searchQuery = ref('')
const options = ref({ page: 1, itemsPerPage: 10 })

// Поля поиска для автокомплита добавления новых пользователей
const searchInput = ref('')
const searchResults = ref<User[]>([])

// Временные поля ввода группы в удобных пользователю величинах
const form = ref({
  name: '',
  traffic_limit_gb: 0,
  speed_limit_mbps: 0,
  sessions_limit: 0,
  duration_days: 0,
})

const headers = [
  { title: 'UID (Имя пользователя)', key: 'uid', sortable: true },
  { title: 'UUID (Идентификатор)', key: 'id', sortable: true },
  { title: 'Статус', key: 'is_active', sortable: true, align: 'center' as const },
  { title: 'Исключить', key: 'actions', sortable: false, align: 'center' as const },
]

// Преобразование байт/kbps для отображения
const formatBytes = (bytes: number) => !bytes ? 'Безлимит' : `${(bytes / (1024 * 1024 * 1024)).toFixed(0)} ГБ`
const formatSpeed = (kbps: number) => !kbps ? 'Максимальная' : `${(kbps / 1024).toFixed(0)} Мбит/с`

const loadGroupData = async () => {
  loadingGroup.value = true
  try {
    const data = await GetGroup(groupId)
    group.value = data
    form.value = {
      name: data.name || '',
      traffic_limit_gb: !data.traffic_limit ? 0 : Math.round(data.traffic_limit / (1024 * 1024 * 1024)),
      speed_limit_mbps: !data.speed_limit ? 0 : Math.round(data.speed_limit / 1024),
      sessions_limit: data.sessions_limit ?? 0,
      duration_days: data.duration_days ?? 0,
    }
  } catch (e) {
    message.error('Не удалось загрузить параметры группы')
    router.push('/groups')
  } finally {
    loadingGroup.value = false
  }
}

const loadMembers = async (
    page = options.value.page,
    itemsPerPage = options.value.itemsPerPage,
    search = searchQuery.value
) => {
  loadingMembers.value = true
  try {
    const offset = (page - 1) * itemsPerPage
    const response = await GetGroupMembers(groupId, offset, itemsPerPage, search)
    members.value = response.items || []
    totalMembers.value = response.total
  } catch (e) {
    message.error('Ошибка загрузки участников группы')
  } finally {
    loadingMembers.value = false
  }
}

const handleOptions = (opts: { page: number; itemsPerPage: number }) => {
  options.value.page = opts.page
  options.value.itemsPerPage = opts.itemsPerPage
  loadMembers(opts.page, opts.itemsPerPage, searchQuery.value)
}

// Поиск пользователей по UID на бэкенде для автокомплита при добавлении
watch(searchInput, async (q) => {
  const query = q?.trim()
  if (!query || query.length < 1) {
    searchResults.value = []
    return
  }
  searchLoading.value = true
  try {
    const response = await GetUsers(0, 15, query)
    searchResults.value = response.items || []
  } catch (e) {
    console.error(e)
  } finally {
    searchLoading.value = false
  }
})

// Наблюдатель строки поиска участников внутри группы
watch(searchQuery, (val) => {
  options.value.page = 1
  loadMembers(1, options.value.itemsPerPage, val)
})

// Наблюдатель за открытием модального окна добавления участника
watch(showAddModal, (visible) => {
  if (visible) {
    setTimeout(() => {
      autocompleteRef.value?.focus();
    }, 150); // Ждем завершения анимации диалога перед фокусом
  }
})

const saveGroupSettings = async () => {
  savingGroup.value = true
  try {
    const payload: SaveGroupRequest = {
      name: form.value.name.trim(),
      traffic_limit: (form.value.traffic_limit_gb || 0) * 1024 * 1024 * 1024,
      speed_limit: (form.value.speed_limit_mbps || 0) * 1024,
      sessions_limit: form.value.sessions_limit ?? 0,
      duration_days: form.value.duration_days ?? 0,
    }
    const updated = await UpdateGroup(groupId, payload)
    group.value = updated
    message.success('Параметры группы успешно сохранены')
  } catch (e: any) {
    message.error(e?.response?.data || 'Не удалось сохранить параметры')
  } finally {
    savingGroup.value = false
  }
}

// Привязать нового пользователя к этой группе
const addSelectedMember = async (userId: any) => {
  if (!userId) return
  try {
    await AddGroupMember(groupId, String(userId))
    message.success('Пользователь добавлен в группу')
    showAddModal.value = false
    searchInput.value = ''
    searchResults.value = []
    options.value.page = 1
    await Promise.all([loadGroupData(), loadMembers(1, options.value.itemsPerPage)])
  } catch (e: any) {
    message.error(e?.response?.data || 'Не удалось добавить пользователя')
  }
}

// Исключить пользователя из группы
const removeMember = async (userId: string, username: string) => {
  if (!confirm(`Исключить пользователя «${username}» из этой группы?`)) return
  try {
    await RemoveGroupMember(groupId, userId)
    message.success('Пользователь исключен из группы')
    options.value.page = 1
    await Promise.all([loadGroupData(), loadMembers(1, options.value.itemsPerPage)])
  } catch (e: any) {
    message.error(e?.response?.data || 'Не удалось исключить пользователя')
  }
}

onMounted(() => {
  loadGroupData()
  loadMembers()
})
</script>

<template>
  <v-container max-width="1200" class="group-detail-page py-6">
    <!-- Навигация назад -->
    <div class="d-flex align-center ga-2 mb-4">
      <v-btn icon="mdi-arrow-left" variant="text" size="small" @click="router.push('/groups')" />
      <span class="text-caption text-medium-emphasis">Назад к списку групп</span>
    </div>

    <!-- Заголовок страницы -->
    <div class="d-flex justify-space-between align-center mb-6">
      <div v-if="group">
        <h2 class="text-h5 font-weight-bold ma-0">{{ group.name }}</h2>
        <span class="text-caption text-medium-emphasis">ID: {{ group.id }}</span>
      </div>
      <v-skeleton-loader v-else type="text" width="200px" />
    </div>

    <v-row>
      <!-- Левая колонка: Редактирование параметров группы -->
      <v-col cols="12" md="4">
        <v-card border flat class="pa-4">
          <div class="text-subtitle-1 font-weight-bold mb-4">Параметры лимитов</div>
          <v-form v-if="group">
            <v-text-field
                v-model="form.name"
                label="Название группы"
                variant="filled"
                class="mb-3"
            />
            <v-text-field
                v-model.number="form.sessions_limit"
                type="number"
                label="Сессий (0 - без лимита)"
                min="0"
                variant="filled"
                class="mb-3"
            />
            <v-text-field
                v-model.number="form.traffic_limit_gb"
                type="number"
                label="Лимит трафика (ГБ, 0 - безлимит)"
                min="0"
                variant="filled"
                class="mb-3"
            />
            <v-text-field
                v-model.number="form.speed_limit_mbps"
                type="number"
                label="Лимит скорости (Мбит/с, 0 - макс)"
                min="0"
                variant="filled"
                class="mb-3"
            />
            <v-text-field
                v-model.number="form.duration_days"
                type="number"
                label="Срок действия (в днях)"
                min="0"
                variant="filled"
                class="mb-4"
            />
            <v-btn
                color="primary"
                block
                :loading="savingGroup"
                :disabled="!form.name.trim()"
                @click="saveGroupSettings"
            >
              Сохранить
            </v-btn>
          </v-form>
          <v-skeleton-loader v-else type="article" />
        </v-card>
      </v-col>

      <!-- Правая колонка: Таблица участников с Lazy load -->
      <v-col cols="12" md="8">
        <v-card border flat class="pa-4">
          <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-4">
            <div class="text-subtitle-1 font-weight-bold">
              Участники группы ({{ totalMembers }})
            </div>
            <div class="d-flex align-center ga-3">
              <v-text-field
                  v-model="searchQuery"
                  prepend-inner-icon="mdi-magnify"
                  label="Поиск по группе..."
                  variant="outlined"
                  density="compact"
                  hide-details
                  single-line
                  style="width: 220px"
              />
              <v-btn color="primary" prepend-icon="mdi-plus" @click="showAddModal = true">
                Добавить участника
              </v-btn>
            </div>
          </div>

          <v-data-table-server
              v-model:items-per-page="options.itemsPerPage"
              v-model:page="options.page"
              :headers="headers"
              :items="members"
              :items-length="totalMembers"
              :loading="loadingMembers"
              items-per-page-text="Строк на странице"
              loading-text="Загрузка списка участников…"
              no-data-text="В этой группе пока нет участников"
              density="comfortable"
              class="members-table border rounded-lg"
              @update:options="handleOptions"
          >
            <template #item.uid="{ item }">
              <span class="uid-col font-weight-medium">{{ item.uid || 'Без имени' }}</span>
            </template>

            <template #item.id="{ item }">
              <span class="uuid-col text-medium-emphasis">{{ item.id }}</span>
            </template>

            <template #item.is_active="{ item }">
              <v-chip :color="item.is_active ? 'success' : 'error'" size="small">
                {{ item.is_active ? 'Active' : 'Banned' }}
              </v-chip>
            </template>

            <template #item.actions="{ item }">
              <v-btn
                  icon="mdi-close-circle-outline"
                  variant="text"
                  color="error"
                  size="small"
                  @click="removeMember(item.id, item.uid)"
              />
            </template>
          </v-data-table-server>
        </v-card>
      </v-col>
    </v-row>

    <!-- Модалка быстрого поиска и привязки нового пользователя -->
    <v-dialog v-model="showAddModal" max-width="500px">
      <v-card class="pa-4">
        <v-card-title class="text-h6 pb-4">Добавить участника в группу</v-card-title>
        <v-card-text>
          <v-autocomplete
              ref="autocompleteRef"
              v-model:search="searchInput"
              :items="searchResults.map(u => ({ title: u.uid || 'No Name', value: u.id }))"
              item-title="title"
              item-value="value"
              :loading="searchLoading"
              label="Начните вводить имя или UID пользователя..."
              no-filter
              hide-no-data
              variant="filled"
              @update:model-value="addSelectedMember"
          />
        </v-card-text>
        <v-card-actions class="px-6 pb-2">
          <v-spacer />
          <v-btn variant="text" @click="showAddModal = false">Отмена</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<style scoped>
.group-detail-page {
  max-width: 1200px;
}
.members-table :deep(tbody tr:hover) {
  background: rgba(255, 255, 255, 0.01) !important;
}
.uuid-col {
  font-family: 'Fira Code', monospace;
  font-size: 13px;
}
</style>
