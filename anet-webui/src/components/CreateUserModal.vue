<script setup lang="ts">
import { ref } from 'vue'
import { CreateUser } from '@/api/users'
import type { CreateUserRequest, User } from '@/models/user'
import { formatDate } from '@/utils'
import { useAppMessage } from '@/composables/useAppMessage'
import UserForm from '@/components/UserForm.vue'

// Обычный v-model (modelValue): родитель связывает v-model="showCreate"
const show = defineModel<boolean>()

const emit = defineEmits<{
  (e: 'created'): void
}>()

const message = useAppMessage()

const rateEnabled = ref(false)
const loading = ref(false)
const formValid = ref(false)

const rateForm = ref({
  sessions: 1,
  date_end: formatDate(new Date(), 'yyyy-MM-dd-HH:mm'),
})

// Черновик User: общие поля редактирует UserForm, справочники грузит он же
const defaultDraft = (): User => ({
  id: '',
  fingerprint: '',
  uid: '',
  is_active: true,
  created_at: '',
  rate: null,
  static_ip: null,
  server_ids: [],
  pool_ids: [],
  route_map_id: null,
})
const draft = ref<User>(defaultDraft())

const rateIsValid = () =>
    Number.isInteger(rateForm.value.sessions)
    && rateForm.value.sessions >= 1
    && !!rateForm.value.date_end

const create = async () => {
  if (!formValid.value) return
  if (rateEnabled.value && !rateIsValid()) {
    message.error('Заполните тариф: сессии — целое число от 1, и дата окончания')
    return
  }
  loading.value = true
  try {
    const payload: CreateUserRequest = {
      uid: draft.value.uid.trim(),
      server_ids: draft.value.server_ids,
      pool_ids: draft.value.pool_ids,
      route_map_id: draft.value.route_map_id,
      rate: rateEnabled.value
          ? {
            sessions: rateForm.value.sessions,
            date_end: rateForm.value.date_end,
          }
          : null,
    }

    await CreateUser(payload)
    message.success(`Пользователь «${payload.uid}» создан`)
    emit('created')
    show.value = false

    draft.value = defaultDraft()
    rateEnabled.value = false
  } catch (e: unknown) {
    const err = e as { response?: { data?: unknown }; message?: string }
    const detail = typeof err.response?.data === 'string'
        ? err.response.data
        : err instanceof Error ? err.message : 'Не удалось создать пользователя'
    message.error(detail)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <v-dialog v-model="show" width="600">
    <v-card>
      <v-card-title class="text-h6 pb-4">Создать пользователя</v-card-title>

      <v-card-text>
        <UserForm v-model="draft" v-model:valid="formValid" creating />

        <v-checkbox
            v-model="rateEnabled"
            label="Create rate"
            density="comfortable"
            hide-details
            class="mt-4 mb-2"
        />

        <template v-if="rateEnabled">
          <v-number-input
              v-model="rateForm.sessions"
              label="Sessions"
              :min="1"
              class="mb-3"
          />

          <v-text-field
              v-model="rateForm.date_end"
              label="Date End"
              type="datetime-local"
              value-format="yyyy-MM-dd-HH:mm"
          />
        </template>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
        <v-btn variant="text" @click="show = false">Cancel</v-btn>
        <v-btn
            color="primary"
            :loading="loading"
            :disabled="!formValid"
            @click="create"
        >
          Create
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
