<script setup lang="ts">
import { computed, ref } from 'vue'
import { GetUsers } from '@/api/users'
import type { UsersResponse } from '@/models/user'

import UserModal from '@/components/UserModal.vue'
import CreateUserModal from '@/components/CreateUserModal.vue'

const data = ref<UsersResponse | null>(null)
const loading = ref(false)

// Пагинация серверная (offset/limit в API), v-data-table лишь сообщает опции
const options = ref({ page: 1, itemsPerPage: 10 })
let optionsInitialized = false

const headers = [
  { title: 'UID (User Name)', key: 'uid' },
  { title: 'UUID (ID)', key: 'id' },
  { title: 'Status', key: 'is_active', align: 'center' as const },
]

const items = computed(() => data.value?.items ?? [])
const total = computed(() => data.value?.total ?? 0)

const loadUsers = async () => {
  loading.value = true
  try {
    const offset = (options.value.page - 1) * options.value.itemsPerPage
    data.value = await GetUsers(offset, options.value.itemsPerPage)
  } finally {
    loading.value = false
  }
}

// Единственная точка смены страницы/размера: встроенный футер таблицы
const handleOptions = (opts: { page: number; itemsPerPage: number }) => {
  const changed = opts.page !== options.value.page || opts.itemsPerPage !== options.value.itemsPerPage
  options.value = { page: opts.page, itemsPerPage: opts.itemsPerPage }
  if (changed || !optionsInitialized) {
    optionsInitialized = true
    loadUsers()
  }
}

// Пустая строка = модалка закрыта, ничего не выбрано
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
    <div class="d-flex justify-space-between align-center mb-5">
      <h2 class="text-h6 font-weight-bold ma-0">ANet VPN Clients</h2>
      <v-btn color="primary" @click="showCreate = true"> Add User </v-btn>
    </div>

    <v-data-table
        :headers="headers"
        :items="items"
        :items-length="total"
        :loading="loading"
        :items-per-page="options.itemsPerPage"
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
    </v-data-table>

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
