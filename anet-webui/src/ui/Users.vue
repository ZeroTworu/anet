<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { GetUsers } from '@/api/users'
import { GetGroups } from '@/api/groups'
import type { UsersResponse, User } from '@/models/user'
import type { UserGroup } from '@/models/group'

import UserModal from '@/components/UserModal.vue'
import CreateUserModal from '@/components/CreateUserModal.vue'

const data = ref<UsersResponse | null>(null)
const loading = ref(false)
const searchQuery = ref('')
const selectedGroupIds = ref<string[]>([])
const groups = ref<UserGroup[]>([])

// Текущие опции пагинации и сортировки
const options = ref({
  page: 1,
  itemsPerPage: 10,
  sortBy: [] as { key: string; order: string }[] // <-- Сюда Vuetify пишет активную сортировку
})

const headers = [
  { title: 'UID (User Name)', key: 'uid', sortable: true },
  { title: 'Группа', key: 'group_name', sortable: false }, // По этой связи сортировка отключена
  { title: 'UUID (ID)', key: 'id', sortable: true },
  { title: 'Status', key: 'is_active', sortable: true, align: 'center' as const },
  { title: 'Действия', key: 'actions', sortable: false, align: 'center' as const },
]

const items = computed(() => data.value?.items ?? [])
const total = computed(() => data.value?.total ?? 0)

const groupMap = computed(() => new Map(groups.value.map(g => [g.id, g])))
const groupOptions = computed(() => groups.value.map(g => ({ title: g.name, value: g.id })))

// Загрузка пользователей
const loadUsers = async (
    page = options.value.page,
    itemsPerPage = options.value.itemsPerPage,
    search = searchQuery.value,
    groupIds = selectedGroupIds.value,
    sortBy = options.value.sortBy
) => {
  loading.value = true
  try {
    const offset = (page - 1) * itemsPerPage
    const sortField = sortBy[0]?.key // Извлекаем поле сортировки
    const isDesc = sortBy[0]?.order === 'desc' // Извлекаем направление

    data.value = await GetUsers(offset, itemsPerPage, search, groupIds, sortField, isDesc)
  } finally {
    loading.value = false
  }
}

const loadGroupDictionary = async () => {
  try {
    groups.value = await GetGroups()
  } catch (e) {
    console.error('Failed to load group dictionary for users list:', e)
  }
}

// При клике на пагинацию или заголовки колонок
const handleOptions = (opts: any) => {
  options.value.page = opts.page
  options.value.itemsPerPage = opts.itemsPerPage
  options.value.sortBy = opts.sortBy || []

  loadUsers(opts.page, opts.itemsPerPage, searchQuery.value, selectedGroupIds.value, opts.sortBy)
}

watch(selectedGroupIds, (newIds) => {
  options.value.page = 1
  loadUsers(1, options.value.itemsPerPage, searchQuery.value, newIds, options.value.sortBy)
})

watch(searchQuery, (query) => {
  options.value.page = 1
  loadUsers(1, options.value.itemsPerPage, query, selectedGroupIds.value, options.value.sortBy)
})

const selectedUserId = ref('')
const showModal = ref(false)
const showCreate = ref(false)

const openEdit = (id: string) => {
  selectedUserId.value = id
  showModal.value = true
}

const closeModal = () => {
  showModal.value = false
  selectedUserId.value = ''
}

onMounted(() => {
  loadGroupDictionary()
  loadUsers()
})
</script>

<template>
  <v-container fluid class="users-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-4">
      <v-list-item
        class="px-0"
        subtitle="Управление учетными записями пользователей, тарифами и привязками к группам"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">ANet VPN Clients (Пользователи)</h1>
        </template>
      </v-list-item>
    </div>

    <div class="d-flex justify-space-between align-center flex-wrap ga-3 mb-4">
      <div class="d-flex align-center flex-wrap ga-3 flex-grow-1">
        <v-text-field
          v-model="searchQuery"
          prepend-inner-icon="mdi-magnify"
          label="Поиск по UID..."
          variant="outlined"
          density="compact"
          hide-details
          single-line
          style="max-width: 280px"
        />

        <v-select
          v-model="selectedGroupIds"
          multiple
          clearable
          chips
          collapse-chips
          :items="groupOptions"
          item-title="title"
          item-value="value"
          label="Фильтр по группам"
          placeholder="Все группы"
          variant="outlined"
          density="compact"
          hide-details
          style="max-width: 320px"
        />
      </div>

      <v-btn color="primary" prepend-icon="mdi-plus" @click="showCreate = true">
        + ДОБАВИТЬ КЛИЕНТА
      </v-btn>
    </div>

    <v-data-table-server
      v-model:items-per-page="options.itemsPerPage"
      v-model:page="options.page"
      :headers="headers"
      :items="items"
      :items-length="total"
      :loading="loading"
      :items-per-page-options="[10, 20, 50, 100]"
      items-per-page-text="Items per page:"
      loading-text="Загрузка пользователей…"
      no-data-text="Пользователи не найдены"
      density="comfortable"
      class="border rounded-lg"
      hover
      @update:options="handleOptions"
      @click:row="(_: unknown, data: { item: { id: string } }) => openEdit(data.item.id)"
    >
      <template #item.uid="{ item }">
        <span class="font-weight-bold">{{ item.uid || 'No Name' }}</span>
      </template>

      <template #item.group_name="{ item }">
        <v-chip
          v-if="item.group_id && groupMap.has(item.group_id)"
          size="small"
          variant="tonal"
          color="secondary"
        >
          {{ groupMap.get(item.group_id)?.name }}
        </v-chip>
        <span v-else class="text-caption text-medium-emphasis">—</span>
      </template>

      <template #item.id="{ item }">
        <code class="text-caption text-medium-emphasis">{{ item.id }}</code>
      </template>

      <template #item.is_active="{ item }">
        <v-chip :color="item.is_active ? 'success' : 'error'" size="small">
          {{ item.is_active ? 'ACTIVE' : 'BANNED' }}
        </v-chip>
      </template>

      <template #item.actions="{ item }">
        <div class="d-flex ga-1 justify-center flex-nowrap" @click.stop>
          <v-btn
            icon="mdi-pencil"
            size="small"
            variant="text"
            title="Редактировать клиента"
            @click="openEdit(item.id)"
          />
        </div>
      </template>
    </v-data-table-server>

    <UserModal
      v-model="showModal"
      :user-id="selectedUserId"
      @updated="loadUsers"
      @close="closeModal"
    />

    <CreateUserModal v-model="showCreate" @created="loadUsers" />
  </v-container>
</template>

<style scoped>
.users-page {
  padding: 24px;
}
</style>
