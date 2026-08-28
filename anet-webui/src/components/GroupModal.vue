<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { CreateGroup, UpdateGroup } from '@/api/groups'
import { GetUsers, GetUser } from '@/api/users'
import type { UserGroup, SaveGroupRequest } from '@/models/group'
import type { User } from '@/models/user'
import { useAppMessage } from '@/composables/useAppMessage'

const show = defineModel<boolean>()

const props = defineProps<{
  group: UserGroup | null
}>()

const emit = defineEmits<{
  (e: 'saved'): void
  (e: 'close'): void
}>()

const loading = ref(false)     // Лоадер кнопки сохранения
const fetching = ref(false)    // Оверлей ("паранджа") первичного резолва участников
const searchLoading = ref(false) // Спиннер внутри поля автокомплита

const message = useAppMessage()

// Хранилище для точечно загруженных участников группы и результатов поиска
const resolvedUsers = ref<User[]>([])
const searchResults = ref<User[]>([])
const searchInput = ref('')
const selectedUserIds = ref<string[]>()

const form = ref({
  name: '',
  traffic_limit_gb: 0,
  speed_limit_mbps: 0,
  sessions_limit: 0,
  duration_days: 0,
})

// Объединяем известных нам пользователей для корректного маппинга UID на чипсах
const allKnownUsers = computed(() => {
  const map = new Map<string, User>()
  resolvedUsers.value.forEach(u => map.set(u.id, u))
  searchResults.value.forEach(u => map.set(u.id, u))
  return Array.from(map.values())
})

const userMap = computed(() => new Map(allKnownUsers.value.map(u => [u.id, u])))

// Доступные для добавления (результаты поиска минус уже выбранные)
const availableUsersToAssign = computed(() => {
  const selectedSet = new Set(selectedUserIds.value || [])
  return searchResults.value
      .filter(u => !selectedSet.has(u.id))
      .map(u => ({ title: u.uid || 'No Name', value: u.id }))
})

const resetForm = () => {
  form.value = {
    name: '',
    traffic_limit_gb: 0,
    speed_limit_mbps: 0,
    sessions_limit: 0,
    duration_days: 0,
  }
  selectedUserIds.value = []
  resolvedUsers.value = []
  searchResults.value = []
  searchInput.value = ''
}

// Загрузка только тех пользователей, которые уже привязаны к группе
const resolveCurrentGroupMembers = async (userIds: string[]) => {
  if (!userIds || userIds.length === 0) {
    resolvedUsers.value = []
    return
  }
  fetching.value = true
  try {
    const promises = userIds.map(id => GetUser(id))
    resolvedUsers.value = await Promise.all(promises)
  } catch (e) {
    console.error('Failed to resolve group members details:', e)
    message.error('Не удалось загрузить имена участников группы')
  } finally {
    fetching.value = false
  }
}

const initForm = (groupVal: UserGroup | null) => {
  if (groupVal) {
    form.value = {
      name: groupVal.name || '',
      traffic_limit_gb: !groupVal.traffic_limit ? 0 : Math.round(groupVal.traffic_limit / (1024 * 1024 * 1024)),
      speed_limit_mbps: !groupVal.speed_limit ? 0 : Math.round(groupVal.speed_limit / 1024),
      sessions_limit: groupVal.sessions_limit ?? 0,
      duration_days: groupVal.duration_days ?? 0,
    }
    selectedUserIds.value = groupVal.user_ids ? [...groupVal.user_ids] : []
  } else {
    resetForm()
  }
}

// Отслеживание ввода в поисковую строку автокомплита (Server-side search)
watch(searchInput, async (query) => {
  const q = query?.trim()
  if (!q || q.length < 1) {
    searchResults.value = []
    return
  }
  searchLoading.value = true
  try {
    const response = await GetUsers(0, 15, q)
    searchResults.value = response.items || []
  } catch (e) {
    console.error('Failed to search users:', e)
  } finally {
    searchLoading.value = false
  }
})

watch(
    () => props.group,
    (newGroup) => {
      initForm(newGroup)
    },
    { immediate: true }
)

watch(show, async (visible) => {
  if (visible) {
    initForm(props.group)
    if (props.group?.user_ids?.length) {
      await resolveCurrentGroupMembers(props.group.user_ids)
    }
  } else {
    resetForm()
  }
})

const addUser = (userId: any) => {
  if (userId) {
    if (!selectedUserIds.value) selectedUserIds.value = []
    if (!selectedUserIds.value.includes(userId)) {
      selectedUserIds.value.push(userId)
    }
    // Очищаем строку поиска после добавления
    searchInput.value = ''
    searchResults.value = []
  }
}

const removeUser = (userId: string) => {
  if (selectedUserIds.value) {
    selectedUserIds.value = selectedUserIds.value.filter(id => id !== userId)
  }
}

const save = async () => {
  loading.value = true
  try {
    const payload: SaveGroupRequest = {
      name: form.value.name.trim(),
      traffic_limit: (form.value.traffic_limit_gb || 0) * 1024 * 1024 * 1024,
      speed_limit: (form.value.speed_limit_mbps || 0) * 1024,
      sessions_limit: form.value.sessions_limit ?? 0,
      duration_days: form.value.duration_days ?? 0,
      user_ids: selectedUserIds.value || [],
    }

    if (props.group?.id) {
      await UpdateGroup(props.group.id, payload)
      message.success('Параметры группы сохранены')
    } else {
      await CreateGroup(payload)
      message.success('Новая группа пользователей создана')
    }
    emit('saved')
    show.value = false
  } catch (e: any) {
    message.error(e?.response?.data || 'Не удалось сохранить настройки')
  } finally {
    loading.value = false
  }
}

const close = () => {
  show.value = false
  emit('close')
}
</script>

<template>
  <v-dialog v-model="show" @update:model-value="close" max-width="650px">
    <v-card class="position-relative">
      <!-- Паранджа-лоадер при резолве существующих пользователей -->
      <v-overlay
          :model-value="fetching"
          contained
          persistent
          class="align-center justify-center"
          scrim="background"
          style="z-index: 10;"
      >
        <v-progress-circular indeterminate color="primary" size="48" />
      </v-overlay>

      <v-card-title class="text-h6 pb-4">
        {{ group ? 'Редактировать группу' : 'Создать группу пользователей' }}
      </v-card-title>

      <v-card-text>
        <v-form>
          <v-row class="mb-1">
            <v-col cols="12" sm="8">
              <v-text-field
                  v-model="form.name"
                  label="Название группы"
                  placeholder="e.g. Администраторы, Гости"
                  variant="filled"
                  hide-details
              />
            </v-col>
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.sessions_limit"
                  type="number"
                  label="Сессий (0 - без лимита)"
                  min="0"
                  variant="filled"
                  hide-details
              />
            </v-col>
          </v-row>

          <v-row class="mb-1">
            <v-col cols="12" sm="6">
              <v-text-field
                  v-model.number="form.traffic_limit_gb"
                  type="number"
                  label="Ограничение трафика (ГБ)"
                  placeholder="0 - безлимитный трафик"
                  variant="filled"
                  hide-details
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-text-field
                  v-model.number="form.speed_limit_mbps"
                  type="number"
                  label="Ограничение скорости (Мбит/с)"
                  placeholder="0 - максимальная скорость"
                  variant="filled"
                  hide-details
              />
            </v-col>
          </v-row>

          <v-row class="mb-4">
            <v-col cols="12">
              <v-text-field
                  v-model.number="form.duration_days"
                  type="number"
                  label="Срок действия доступа при активации (в днях)"
                  min="0"
                  placeholder="0 - бессрочный доступ"
                  variant="filled"
                  hide-details
              />
            </v-col>
          </v-row>

          <v-divider class="my-4" />

          <div class="text-subtitle-2 mb-2 font-weight-bold">
            Пользователи в группе ({{ selectedUserIds?.length || 0 }}):
          </div>

          <!-- Поиск с ленивой загрузкой и фильтрацией на сервере -->
          <v-autocomplete
              v-model:search="searchInput"
              :items="availableUsersToAssign"
              item-title="title"
              item-value="value"
              :loading="searchLoading"
              label="Добавить пользователя в эту группу"
              placeholder="Введите имя пользователя для поиска..."
              variant="filled"
              hide-no-data
              hide-details
              no-filter
              class="mb-3"
              @update:model-value="addUser"
          />

          <v-sheet border rounded="lg" class="pa-3 mb-2" style="max-height: 140px; overflow-y: auto;">
            <div class="d-flex flex-wrap ga-2">
              <v-chip
                  v-for="userId in selectedUserIds"
                  :key="userId"
                  closable
                  variant="tonal"
                  color="primary"
                  size="small"
                  @click:close="removeUser(userId)"
              >
                {{ userMap.get(userId)?.uid || 'Без имени' }}
              </v-chip>
              <div v-if="!selectedUserIds?.length" class="text-caption text-medium-emphasis py-2 text-center w-100">
                В этой группе пока нет пользователей. Воспользуйтесь строкой поиска выше.
              </div>
            </div>
          </v-sheet>
        </v-form>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
        <v-btn variant="text" @click="close">Отмена</v-btn>
        <v-btn
            color="primary"
            variant="flat"
            :loading="loading"
            :disabled="!form.name.trim() || form.sessions_limit < 0 || form.duration_days < 0"
            @click="save"
        >
          Сохранить
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.position-relative {
  position: relative !important;
}
</style>
