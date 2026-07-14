<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import type { User } from '@/models/user'
import { GetServers } from '@/api/servers'
import type { Server } from '@/models/server'

const user = defineModel<User>('modelValue', {
  required: true,
})

const availableServers = ref<Server[]>([])

// Форматируем список серверов под опции n-select
const serverOptions = computed(() => {
  return availableServers.value.map(s => ({
    label: `${s.name} (${s.address})`,
    value: s.id,
  }))
})

onMounted(async () => {
  try {
    // Загружаем список серверов строго в момент монтирования формы
    availableServers.value = await GetServers()

    // Защита: гарантируем, что server_ids инициализирован как массив
    if (!user.value.server_ids) {
      user.value.server_ids = []
    }
  } catch (e) {
    console.error("Failed to fetch servers inside form:", e)
  }
})
</script>

<template>
  <n-form>
    <!-- UID (editable) -->
    <n-form-item label="UID">
      <n-input v-model:value="user.uid" />
    </n-form-item>

    <!-- Active (editable) -->
    <n-form-item label="Active">
      <n-switch v-model:value="user.is_active" />
    </n-form-item>

    <!-- Static IP (editable) -->
    <n-form-item label="Static IP">
      <n-input v-model:value="user.static_ip" placeholder="e.g. 10.0.0.10" />
    </n-form-item>

    <!-- ВЫБОР СЕРВЕРОВ (Many-to-Many) -->
    <n-form-item label="Привязанные сервера (Локации)">
      <n-select
          v-model:value="user.server_ids"
          multiple
          :options="serverOptions"
          placeholder="Выберите сервера для этого пользователя"
      />
    </n-form-item>

    <n-divider />

    <!-- Readonly fields -->
    <n-form-item label="Fingerprint">
      <n-input :value="user.fingerprint" disabled />
    </n-form-item>

    <n-form-item label="Created At">
      <n-input :value="user.created_at" disabled />
    </n-form-item>
  </n-form>
</template>
