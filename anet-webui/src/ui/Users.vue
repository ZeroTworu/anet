<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { getUsers } from '@/api/users'
import type { UsersResponse } from '@/api/users'

const data = ref<UsersResponse | null>(null)
const loading = ref(false)


const loadUsers = async() => {
  loading.value = true

  try {
    data.value = await getUsers(0,10)
  } finally {
    loading.value = false
  }
}

onMounted(loadUsers)
</script>

<template>
  <div v-if="loading">Loading...</div>

  <div v-else-if="data">
    <p>Total: {{ data.total }}</p>

    <ul>
      <li v-for="item in data.items" :key="item.id">
        {{ item.uid }} - {{ item.id }}
      </li>
    </ul>
  </div>
</template>

<style scoped></style>
