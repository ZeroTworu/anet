<script setup lang="ts">
import { computed, ref } from 'vue'
import { GetUsers } from '@/api/users'
import type { UsersResponse } from '@/models/user'

import UserModal from '@/components/UserModal.vue'
import CreateUserModal from '@/components/CreateUserModal.vue'

const data = ref<UsersResponse | null>(null)
const loading = ref(false)
const searchQuery = ref('')

// Текущие опции пагинации
const options = ref({ page: 1, itemsPerPage: 10 })

const headers = [
  { title: 'UID (User Name)', key: 'uid', sortable: true },
  { title: 'UUID (ID)', key: 'id', sortable: true },
  { title: 'Status', key: 'is_active', sortable: true, align: 'center' as const },
]

const items = computed(() => data.value?.items ?? [])
const total = computed(() => data.value?.total ?? 0)

// Функция загрузки с безопасными параметрами по умолчанию
const loadUsers = async (
    page: number = options.value.page,
    itemsPerPage: number = options.value.itemsPerPage,
    search: string = searchQuery.value
) => {
  loading.value = true
  try {
    const offset = (page - 1) * itemsPerPage
    data.value = await GetUsers(offset, itemsPerPage, search)
  } finally {
    loading.value = false
  }
}

// Единая точка входа для любых изменений таблицы (поиск, страница, размер страницы)
const handleOptions = (opts: { page: number; itemsPerPage: number }) => {
  options.value.page = opts.page
  options.value.itemsPerPage = opts.itemsPerPage
  loadUsers(opts.page, opts.itemsPerPage, searchQuery.value)
}

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
</script>

<template>
  <v-container max-width="1200" class="users-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-5">
      <div>
        <h2 class="text-h6 font-weight-bold ma-0">ANet VPN Clients</h2>
        <span class="text-caption text-medium-emphasis">Управление учетными записями пользователей</span>
      </div>
      <div class="d-flex align-center ga-3">
        <v-text-field
            v-model="searchQuery"
            prepend-inner-icon="mdi-magnify"
            label="Поиск по UID..."
            variant="outlined"
            density="compact"
            hide-details
            single-line
            style="width: 260px"
        />
        <v-btn color="primary" @click="showCreate = true"> Add User </v-btn>
      </div>
    </div>

    <v-data-table-server
        v-model:items-per-page="options.itemsPerPage"
        v-model:page="options.page"
        :headers="headers"
        :items="items"
        :items-length="total"
        :loading="loading"
        :search="searchQuery"
        :items-per-page-options="[10, 20, 50, 100]"
        items-per-page-text="Строк на странице"
        loading-text="Загрузка пользователей…"
        no-data-text="Пользователи не найдены"
        density="comfortable"
        class="users-table"
        hover
        @update:options="handleOptions"
        @click:row="(_: unknown, data: { item: { id: string } }) => openEdit(data.item.id)"
    >
      <template #item.uid="{ item }">
        <span class="uid-col">{{ item.uid || 'No Name' }}</span>
      </template>

      <template #item.id="{ item }">
        <span class="uuid-col">{{ item.id }}</span>
      </template>

      <template #item.is_active="{ item }">
        <v-chip :color="item.is_active ? 'success' : 'error'" size="small">
          {{ item.is_active ? 'Active' : 'Banned' }}
        </v-chip>
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
.users-page { padding: 24px; }
.users-table { border-radius: 10px; }
.users-table :deep(tbody tr) { cursor: pointer; }
.users-table :deep(tbody tr:hover) { background: rgba(43, 184, 148, .07) !important; }
.uid-col { font-weight: 600; font-size: 15px; }
.uuid-col { font-family: 'Fira Code', 'Courier New', Courier, monospace; color: #9aa5a0; font-size: 13.5px; }
</style>
