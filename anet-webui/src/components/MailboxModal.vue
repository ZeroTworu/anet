<script setup lang="ts">
import { ref, watch } from 'vue'
import { CreateMailbox, UpdateMailbox } from '@/api/mailboxes'
import type { CreateImapMailboxRequest, ImapMailbox, UpdateImapMailboxRequest } from '@/models/mailbox'
import { useAppMessage } from '@/composables/useAppMessage'

const show = defineModel<boolean>()

const props = defineProps<{
  mailbox: ImapMailbox | null
}>()

const emit = defineEmits<{
  (e: 'saved'): void
  (e: 'close'): void
}>()

const message = useAppMessage()

const host = ref('imap.mail.ru')
const port = ref(993)
const email = ref('')
const clientPassword = ref('')
const serverPassword = ref('')
const isActive = ref(true)
const showPassword = ref(false)
const loading = ref(false)

watch(
  () => props.mailbox,
  (m) => {
    if (m) {
      host.value = m.host
      port.value = m.port
      email.value = m.email
      clientPassword.value = ''
      serverPassword.value = ''
      isActive.value = m.is_active
    } else {
      host.value = 'imap.mail.ru'
      port.value = 993
      email.value = ''
      clientPassword.value = ''
      serverPassword.value = ''
      isActive.value = true
    }
  },
  { immediate: true }
)

const save = async () => {
  if (!host.value.trim() || !email.value.trim()) {
    message.error('Укажите хост и email')
    return
  }
  if (!props.mailbox && !clientPassword.value.trim()) {
    message.error('Введите пароль приложения для клиентов')
    return
  }

  loading.value = true
  try {
    if (props.mailbox) {
      const payload: UpdateImapMailboxRequest = {
        host: host.value.trim(),
        port: port.value || 993,
        email: email.value.trim(),
        client_password: clientPassword.value.trim() || null,
        server_password: serverPassword.value.trim() || null,
        is_active: isActive.value,
      }
      await UpdateMailbox(props.mailbox.id, payload)
      message.success('Почтовый ящик успешно обновлен')
    } else {
      const payload: CreateImapMailboxRequest = {
        host: host.value.trim(),
        port: port.value || 993,
        email: email.value.trim(),
        client_password: clientPassword.value.trim(),
        server_password: serverPassword.value.trim() || null,
        is_active: isActive.value,
      }
      await CreateMailbox(payload)
      message.success('Почтовый ящик успешно добавлен')
    }
    emit('saved')
    show.value = false
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка сохранения'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  } finally {
    loading.value = false
  }
}

const close = () => {
  show.value = false
  emit('close')
}
</script>

<template>
  <v-dialog v-model="show" @update:model-value="close" max-width="600px">
    <v-card class="rounded-lg">
      <v-card-title class="text-h6 pt-5 px-6 pb-2">
        {{ mailbox ? 'Редактировать почтовый ящик' : 'Добавить почтовый ящик IMAP' }}
      </v-card-title>
      <v-card-subtitle class="px-6 pb-4 text-caption text-medium-emphasis">
        Служебный аккаунт для передачи трафика через черновики и заметки
      </v-card-subtitle>

      <v-divider />

      <v-card-text class="pa-6">
        <v-form @submit.prevent="save">
          <v-row dense>
            <v-col cols="12" sm="8">
              <v-text-field
                v-model="host"
                label="Хост IMAP сервера"
                placeholder="imap.mail.ru"
                variant="outlined"
                density="compact"
                hide-details="auto"
                class="mb-3"
              />
            </v-col>
            <v-col cols="12" sm="4">
              <v-text-field
                v-model.number="port"
                type="number"
                label="Порт IMAPS"
                placeholder="993"
                variant="outlined"
                density="compact"
                hide-details="auto"
                class="mb-3"
              />
            </v-col>
          </v-row>

          <v-text-field
            v-model="email"
            label="Email (логин)"
            placeholder="acc1@mail.ru"
            prepend-inner-icon="mdi-email-outline"
            variant="outlined"
            density="compact"
            hide-details="auto"
            class="mb-3"
          />

          <v-text-field
            v-model="clientPassword"
            :type="showPassword ? 'text' : 'password'"
            label="Пароль приложения (для Клиентов)"
            :placeholder="mailbox ? 'Оставьте пустым, чтобы не изменять' : 'Сгенерированный пароль приложения'"
            :append-inner-icon="showPassword ? 'mdi-eye-off' : 'mdi-eye'"
            prepend-inner-icon="mdi-key-variant"
            variant="outlined"
            density="compact"
            hide-details="auto"
            class="mb-3"
            @click:append-inner="showPassword = !showPassword"
          />

          <v-text-field
            v-model="serverPassword"
            :type="showPassword ? 'text' : 'password'"
            label="Отдельный пароль сервера (опционально)"
            placeholder="Если не задан, сервер использует пароль клиента"
            prepend-inner-icon="mdi-server-security"
            variant="outlined"
            density="compact"
            hide-details="auto"
            class="mb-4"
          />

          <v-switch
            v-model="isActive"
            label="Активен (доступен для пулов)"
            color="success"
            hide-details
          />
        </v-form>
      </v-card-text>

      <v-divider />

      <v-card-actions class="px-6 py-4">
        <v-spacer />
        <v-btn variant="text" @click="close">Отмена</v-btn>
        <v-btn
          color="primary"
          variant="flat"
          :loading="loading"
          :disabled="!host.trim() || !email.trim()"
          @click="save"
        >
          Сохранить
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
