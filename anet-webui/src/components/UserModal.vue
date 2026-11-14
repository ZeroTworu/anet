<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { useAppMessage } from '@/composables/useAppMessage'
import UserForm from './UserForm.vue'
import RateEditForm from './RateEditForm.vue'
import RateCreateForm from './RateCreateForm.vue'
import { useUser } from '@/composables/useUser'
import { useRate } from '@/composables/useRate'

const show = defineModel<boolean>()
const props = defineProps<{
  userId: string
}>()
const emit = defineEmits<{
  (e: 'updated'): void
  (e: 'close'): void
}>()

const {
  user,
  passwordInput,
  clearPasswordFlag,
  loading,
  regenerating,
  loadUser,
  saveUser,
  regenerate,
} = useUser()
const { saving, saveRate, createRate, deleteRate } = useRate(user)
const message = useAppMessage()
const savingUser = ref(false)
const formValid = ref(true)

// Прямая ссылка на скачивание client.toml
const directConfigLink = computed(() => {
  if (!user.value) return ''
  return `${window.location.origin}/api/v1/config/${user.value.id}`
})

// Ссылка на веб-страницу со стильным QR-кодом
const qrPageLink = computed(() => {
  if (!user.value) return ''
  return `${window.location.origin}/api/v1/config/qr/${user.value.id}`
})

const copyToClipboard = (text: string, successMessage: string) => {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard
      .writeText(text)
      .then(() => message.success(successMessage))
      .catch(() => message.error('Failed to copy link.'))
  } else {
    const textArea = document.createElement('textarea')
    textArea.value = text
    textArea.style.position = 'fixed'
    textArea.style.left = '-9999px'
    textArea.style.top = '-9999px'
    document.body.appendChild(textArea)
    textArea.focus()
    textArea.select()

    try {
      if (document.execCommand('copy')) {
        message.success(successMessage)
      } else {
        message.error('Failed to copy link.')
      }
    } catch {
      message.error('Failed to copy link.')
    }
    document.body.removeChild(textArea)
  }
}

const copyDirectLink = () => {
  if (!directConfigLink.value) return
  copyToClipboard(directConfigLink.value, 'Прямая ссылка на client.toml скопирована!')
}

const copyQrPageLink = () => {
  if (!qrPageLink.value) return
  copyToClipboard(qrPageLink.value, 'Ссылка на страницу с QR-кодом скопирована!')
}

watch(
  () => props.userId,
  (id) => {
    // Пустая строка — модалка закрыта, пользователя не загружаем
    if (id) loadUser(id)
  },
  { immediate: true },
)

const close = () => {
  show.value = false
  user.value = null
  passwordInput.value = ''
  clearPasswordFlag.value = false
  emit('close')
}

const extractErr = (e: unknown, fallback: string) => {
  const err = e as { response?: { data?: unknown }; message?: string }
  if (typeof err?.response?.data === 'string') return err.response.data
  if (err instanceof Error && err.message) return err.message
  return fallback
}

const handleSaveUser = async () => {
  if (!formValid.value) return
  savingUser.value = true
  try {
    await saveUser()
    message.success('Данные пользователя сохранены')
    emit('updated')
    close()
  } catch (e) {
    message.error(extractErr(e, 'Не удалось сохранить пользователя'))
  } finally {
    savingUser.value = false
  }
}

const handleRegenerate = async () => {
  try {
    await regenerate()
    message.success('Ключи пользователя перегенерированы')
    emit('updated')
  } catch (e) {
    message.error(extractErr(e, 'Не удалось перегенерировать ключи'))
  }
}

const handleRateChange = async (fn: () => Promise<void>) => {
  await fn()
  emit('updated')
}
</script>

<template>
  <v-dialog v-model="show" scrollable @update:model-value="close" max-width="900px">
    <v-card class="pa-6 d-flex flex-column" style="max-height: 85vh;">
      <v-card-title class="text-h6 px-0 pb-4 flex-shrink-0">
        Редактировать пользователя
      </v-card-title>

      <!-- Кнопка прямого скачивания файла (Фокусируется и нажимается с пульта) -->
      <v-btn
        :href="directConfigLink"
        download
        color="success"
        variant="flat"
        block
        prepend-icon="mdi-download"
        class="mb-4"
      >
        Скачать client.toml на устройство
      </v-btn>

      <v-card-text class="px-0 flex-grow-1" style="overflow-y: auto;">
        <v-skeleton-loader v-if="loading && !user" type="article" />

        <!-- Форма юзера -->
        <UserForm
          v-if="user"
          v-model="user"
          v-model:password="passwordInput"
          v-model:clear-password="clearPasswordFlag"
          v-model:valid="formValid"
        />

        <div v-if="user" class="mt-4">
          <RateEditForm
            v-if="user?.rate"
            v-model="user"
            :saving="saving"
            @save="handleRateChange(saveRate)"
            @delete="handleRateChange(deleteRate)"
          />
          <RateCreateForm
            v-else
            :saving="saving"
            @create="(payload) => handleRateChange(() => createRate(payload))"
          />
        </div>

        <!-- КОМПАКТНЫЙ БЛОК ДЛЯ ССЫЛОК И ШЕРИНГА -->
        <v-card v-if="user" variant="outlined" class="mt-6 pa-4">
          <div class="text-subtitle-2 mb-3">🔗 Получить конфигурацию</div>

          <v-text-field
            readonly
            :model-value="directConfigLink"
            label="Прямая ссылка на скачивание client.toml"
            variant="filled"
            density="compact"
            hide-details
            class="link-field mb-3"
          >
            <template #append>
              <v-btn color="primary" variant="tonal" @click="copyDirectLink">Copy</v-btn>
            </template>
          </v-text-field>

          <v-text-field
            readonly
            :model-value="qrPageLink"
            label="Ссылка на веб-страницу с QR-кодом"
            variant="filled"
            density="compact"
            hide-details
            class="link-field"
          >
            <template #append>
              <v-btn color="info" variant="tonal" @click="copyQrPageLink">Copy</v-btn>
            </template>
          </v-text-field>
        </v-card>
      </v-card-text>

      <v-divider class="my-4 flex-shrink-0" />

      <v-card-actions class="px-0 pb-0 justify-space-between flex-shrink-0">
        <v-btn color="warning" variant="text" :loading="regenerating" @click="handleRegenerate">
          Regenerate Keys
        </v-btn>
        <div class="d-flex ga-2">
          <v-btn variant="text" @click="close">Close</v-btn>
          <v-btn
            color="primary"
            variant="flat"
            :loading="savingUser"
            :disabled="!formValid"
            @click="handleSaveUser"
          >
            Save User
          </v-btn>
        </div>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.link-field :deep(input) {
  font-family: 'Fira Code', monospace;
  font-size: 13px;
}
</style>
