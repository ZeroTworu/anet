<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { GetUsers } from '@/api/users'
import type { UsersResponse } from '@/models/user'

import UserModal from '@/components/UserModal.vue'
import CreateUserModal from '@/components/CreateUserModal.vue'

const data = ref<UsersResponse | null>(null)
const loading = ref(false)

const selectedUserId = ref<string | null>(null)
const showModal = ref(false)
const showCreate = ref(false)

const loadUsers = async () => {
  loading.value = true
  try {
    data.value = await GetUsers(0, 10)
  } finally {
    loading.value = false
  }
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
  <!-- ЕДИНЫЙ КОРНЕВОЙ ЭЛЕМЕНТ ( divs ) ДЛЯ ВСЕЙ СТРАНИЦЫ -->
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
