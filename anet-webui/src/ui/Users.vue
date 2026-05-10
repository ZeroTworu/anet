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
  <n-space justify="space-between">
    <div style="display: flex; justify-content: end; padding: 10px">
      <n-button type="primary" @click="showCreate = true"> Add User </n-button>
    </div>
  </n-space>
  <n-spin :show="loading">
    <n-table v-if="data">
      <tbody>
        <tr v-for="item in data.items" :key="item.id" @click="openEdit(item.id)">
          <td>{{ item.uid }}</td>
          <td>{{ item.id }}</td>
          <td>
            <n-tag :type="item.is_active ? 'success' : 'error'">
              {{ item.is_active }}
            </n-tag>
          </td>
        </tr>
      </tbody>
    </n-table>
  </n-spin>

  <UserModal
    v-model:show="showModal"
    :user-id="selectedUserId"
    @updated="loadUsers"
    @close="closeModal"
  />

  <CreateUserModal v-model:show="showCreate" @created="loadUsers" />
</template>
