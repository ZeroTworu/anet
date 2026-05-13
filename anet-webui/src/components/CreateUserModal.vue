<script setup lang="ts">
import { ref, watch } from 'vue'
import { CreateUser } from '@/api/users'
import type { CreateUserRequest } from '@/models/user'
import { formatDate } from '@/utils'

const show = defineModel<boolean>('show')

const emit = defineEmits<{
  (e: 'created'): void
}>()

const rateEnabled = ref(false)

const rateForm = ref({
  sessions: 0,
  date_end: formatDate(new Date(), 'yyyy-MM-dd-HH:mm'),
})

const form = ref<CreateUserRequest>({
  uid: '',
  rate: null,
})

const loading = ref(false)

const create = async () => {
  loading.value = true
  try {
    const payload: CreateUserRequest = {
      uid: form.value.uid,
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

    form.value = { uid: '', rate: null }
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
        <n-input v-model:value="form.uid" />
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
