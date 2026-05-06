<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { GetUsers, SaveUser } from '@/api/users'
import type { User, UsersResponse } from '@/api/users'

const data = ref<UsersResponse | null>(null)
const loading = ref(false)

const selectedUser = ref<User | null>(null)
const showModal = ref(false)

const loadUsers = async () => {
  loading.value = true

  try {
    data.value = await GetUsers(0, 10)
  } finally {
    loading.value = false
  }
}

const openEdit = (user: User) => {
  selectedUser.value = { ...user }
  showModal.value = true
}

const closeModal = () => {
  showModal.value = false
  selectedUser.value = null
}
const saveUser = async () => {
  if (!selectedUser.value) return

  SaveUser(selectedUser.value)

  await loadUsers()
  closeModal()
}
onMounted(loadUsers)
</script>

<template>
  <n-spin :show="loading">
    <n-table v-if="data">
      <thead>
        <tr>
          <th>UID</th>
          <th>ID</th>
          <th>Active</th>
        </tr>
      </thead>

      <tbody>
        <tr
          v-for="item in data.items"
          :key="item.id"
          @click="openEdit(item)"
          style="cursor: pointer"
        >
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
  <n-modal v-model:show="showModal">
    <n-card style="width: 600px" title="Edit user" :bordered="false">
      <n-form v-if="selectedUser">
        <n-form-item label="UID">
          <n-input v-model:value="selectedUser.uid" />
        </n-form-item>

        <n-form-item label="Active">
          <n-switch v-model:value="selectedUser.is_active" />
        </n-form-item>

        <n-form-item label="Rate">
          <n-input-number v-model:value="selectedUser.rate" />
        </n-form-item>

        <n-form-item label="Static IP">
          <n-input v-model:value="selectedUser.static_ip" />
        </n-form-item>
      </n-form>

      <template #footer>
        <n-space justify="end">
          <n-button @click="closeModal">Cancel</n-button>
          <n-button type="primary" @click="saveUser">Save</n-button>
        </n-space>
      </template>
    </n-card>
  </n-modal>
</template>

<style scoped></style>
