<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { CreateUser } from '@/api/users'
import { GetServers } from '@/api/servers'
import type { CreateUserRequest } from '@/models/user'
import type { Server } from '@/models/server'
import { formatDate } from '@/utils'

const show = defineModel<boolean>('show')

const emit = defineEmits<{
  (e: 'created'): void
}>()

const rateEnabled = ref(false)
const availableServers = ref<Server[]>([])

const rateForm = ref({
  sessions: 0,
  date_end: formatDate(new Date(), 'yyyy-MM-dd-HH:mm'),
})

const form = ref({
  uid: '',
  server_ids: [] as string[], // Новое поле массива серверов
})

const loading = ref(false)

const loadServers = async () => {
  try {
    availableServers.value = await GetServers()
  } catch (e) {
    console.error(e)
  }
}

const serverOptions = computed(() => {
  return availableServers.value.map(s => ({
    label: `${s.name} (${s.address})`,
    value: s.id,
  }))
})

onMounted(loadServers)

const create = async () => {
  loading.value = true
  try {
    const payload: CreateUserRequest = {
      uid: form.value.uid,
      server_ids: form.value.server_ids, // <--- Улетает массив привязки при создании!
      rate: rateEnabled.value
          ? {
            sessions: rateForm.value.sessions,
            date_end: rateForm.value.date_end,
          }
          : null,
    }

    await CreateUser(payload)
    emit('created')
    show.value = false

    form.value = { uid: '', server_ids: [] }
    rateEnabled.value = false
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <n-modal v-model:show="show" preset="card" style="width: 600px">
    <n-form>
      <n-form-item label="UID">
        <n-input v-model:value="form.uid" placeholder="e.g. Koshka_Vasya" />
      </n-form-item>

      <!-- ПРИВЯЗКА К СЕРВЕРАМ НА СТАРТЕ -->
      <n-form-item label="Привязать к серверам">
        <n-select
            v-model:value="form.server_ids"
            multiple
            :options="serverOptions"
            placeholder="Выберите локации"
        />
      </n-form-item>

      <n-form-item>
        <n-checkbox v-model:checked="rateEnabled"> Create rate </n-checkbox>
      </n-form-item>

      <div v-if="rateEnabled">
        <n-form-item label="Sessions">
          <n-input-number v-model:value="rateForm.sessions" />
        </n-form-item>

        <n-form-item label="Date End">
          <n-date-picker
              v-model:formatted-value="rateForm.date_end"
              type="datetime"
              value-format="yyyy-MM-dd-HH:mm"
          />
        </n-form-item>
      </div>
    </n-form>
    <template #footer>
      <n-space justify="end">
        <n-button @click="show = false">Cancel</n-button>
        <n-button type="primary" :loading="loading" @click="create"> Create </n-button>
      </n-space>
    </template>
  </n-modal>
</template>
