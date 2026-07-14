<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { GetUsers } from '@/api/users'
import type { UsersResponse } from '@/models/user'

import UserModal from '@/components/UserModal.vue'
import CreateUserModal from '@/components/CreateUserModal.vue'

const data = ref<UsersResponse | null>(null)
const loading = ref(false)

// Состояние пагинации
const page = ref(1)
const pageSize = ref(10)

// Опции для выбора количества элементов на странице
const pageSizeOptions = [
  { label: '10 / стр', value: 10 },
  { label: '20 / стр', value: 20 },
  { label: '50 / стр', value: 50 },
  { label: '100 / стр', value: 100 }
]

const selectedUserId = ref<string | null>(null)
const showModal = ref(false)
const showCreate = ref(false)

const loadUsers = async () => {
  loading.value = true
  try {
    const offset = (page.value - 1) * pageSize.value
    data.value = await GetUsers(offset, pageSize.value)
  } finally {
    loading.value = false
  }
}

// Переключение страниц
const handlePageChange = (direction: 'prev' | 'next') => {
  if (direction === 'prev' && page.value > 1) {
    page.value--
    loadUsers()
  } else if (direction === 'next' && data.value && page.value * pageSize.value < data.value.total) {
    page.value++
    loadUsers()
  }
}

// Изменение размера страницы
const handlePageSizeChange = (value: number) => {
  pageSize.value = value
  page.value = 1 // Сброс на первую страницу
  loadUsers()
}

const openEdit = (id: string) => {
  selectedUserId.value = id
  showModal.value = true
}

const closeModal = () => {
  showModal.value = false
  selectedUserId.value = null
}

onMounted(loadUsers)
</script>

<template>
  <div style="padding: 24px; max-width: 1200px; margin: 0 auto;">
    <n-space justify="space-between" align="center" style="margin-bottom: 20px;">
      <h2 style="margin: 0; font-weight: 600; font-size: 20px;">ANet VPN Clients</h2>
      <n-button type="primary" @click="showCreate = true"> Add User </n-button>
    </n-space>

    <n-spin :show="loading">
      <div class="table-container" v-if="data">
        <n-table :bordered="true" :single-line="false" class="interactive-table">
          <thead>
          <tr>
            <th style="width: 25%">UID (User Name)</th>
            <th style="width: 50%">UUID (ID)</th>
            <th style="width: 15%">Status</th>
          </tr>
          </thead>
          <tbody>
          <tr
              v-for="item in data.items"
              :key="item.id"
              @click="openEdit(item.id)"
              class="clickable-row"
          >
            <td class="uid-col">{{ item.uid || 'No Name' }}</td>
            <td class="uuid-col">{{ item.id }}</td>
            <td>
              <n-tag :type="item.is_active ? 'success' : 'error'" round>
                {{ item.is_active ? 'Active' : 'Banned' }}
              </n-tag>
            </td>
          </tr>
          </tbody>
        </n-table>
      </div>

      <!-- Кастомная панель пагинации -->
      <n-space justify="space-between" align="center" style="margin-top: 20px;" v-if="data">
        <!-- Выбор количества записей -->
        <n-space align="center">
          <span style="color: #94a3b8; size: 13px;">Показано {{ data.items.length }} из {{ data.total }}</span>
          <n-select
              v-model:value="pageSize"
              :options="pageSizeOptions"
              style="width: 120px"
              @update:value="handlePageSizeChange"
          />
        </n-space>

        <!-- Кнопки управления страницами -->
        <n-space align="center">
          <n-button
              :disabled="page === 1"
              @click="handlePageChange('prev')"
          >
            ← СЮДА
          </n-button>

          <span style="font-family: monospace; min-width: 40px; text-align: center;">
            {{ page }}
          </span>

          <n-button
              :disabled="page * pageSize >= data.total"
              @click="handlePageChange('next')"
          >
            ТУДА →
          </n-button>
        </n-space>
      </n-space>
    </n-spin>

    <UserModal
        v-model:show="showModal"
        :user-id="selectedUserId"
        @updated="loadUsers"
        @close="closeModal"
    />

    <CreateUserModal v-model:show="showCreate" @created="loadUsers" />
  </div>
</template>

<style scoped>
.table-container {
  background: #ffffff !important;
  border-radius: 8px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
  border: 1px solid #dcdcdc !important;
  overflow: hidden;
}

.interactive-table :deep(td) {
  background-color: transparent !important;
  border-bottom: 1px solid #e2e8f0 !important;
  padding: 16px 20px !important;
}

.interactive-table :deep(th) {
  background-color: #f1f5f9 !important;
  color: #0f172a !important;
  font-weight: 700 !important;
  border-bottom: 2px solid #cbd5e1 !important;
}

.clickable-row {
  background-color: #ffffff !important;
  cursor: pointer;
  border-left: 4px solid transparent;
  transition: all 0.15s ease-in-out;
}

.clickable-row:nth-child(even) {
  background-color: #f8fafc !important;
}

.clickable-row:hover {
  border-left: 4px solid #18a058 !important;
  background-color: #f0fdf4 !important;
}

.uid-col {
  font-weight: 600 !important;
  color: #0f172a !important;
  font-size: 15px !important;
}

.uuid-col {
  font-family: 'Fira Code', 'Courier New', Courier, monospace !important;
  color: #475569 !important;
  font-size: 13.5px !important;
}

@media (prefers-color-scheme: dark) {
  .table-container {
    background: #18181c !important;
    border: 1px solid #2d3748 !important;
  }
  .interactive-table :deep(th) {
    background-color: #2d3748 !important;
    color: #ffffff !important;
    border-bottom: 2px solid #4a5568 !important;
  }
  .interactive-table :deep(td) {
    border-bottom: 1px solid #2d3748 !important;
  }
  .clickable-row {
    background-color: #18181c !important;
  }
  .clickable-row:nth-child(even) {
    background-color: #1f1f23 !important;
  }
  .clickable-row:hover {
    background-color: #1a3a2a !important;
    border-left: 4px solid #18a058 !important;
  }
  .uid-col {
    color: #ffffff !important;
  }
  .uuid-col {
    color: #94a3b8 !important;
  }
}
</style>
