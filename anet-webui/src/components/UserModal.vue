<script setup lang="ts">
import { watch, computed } from 'vue'
import { useAppMessage } from '@/composables/useAppMessage'

import UserForm from './UserForm.vue'
import RateEditForm from './RateEditForm.vue'
import RateCreateForm from './RateCreateForm.vue'

import { useUser } from '@/composables/useUser'
import { useRate } from '@/composables/useRate'

const show = defineModel<boolean>('show')

const props = defineProps<{
  userId: string | null
}>()

const emit = defineEmits<{
  (e: 'updated'): void
  (e: 'close'): void
}>()

const { user, loading, regenerating, loadUser, saveUser, regenerate } = useUser()
const { saving, saveRate, createRate } = useRate(user)

const message = useAppMessage()

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
    navigator.clipboard.writeText(text)
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
    } catch (err) {
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
      if (id) loadUser(id)
    },
    { immediate: true },
)

const close = () => {
  show.value = false
  user.value = null
  emit('close')
}

const handleSaveUser = async () => {
  await saveUser()
  emit('updated')
  close()
}
</script>

<template>
  <v-dialog
      v-model="show"
      @update:modelValue="close"
      max-width="900px"
  >
    <v-card class="pa-6">
      <v-card-title class="text-h6 px-0 pb-4">
        {{ userId ? 'Редактировать пользователя' : 'Создать пользователя' }}
      </v-card-title>

      <v-card-text class="px-0">
        <!-- Форма юзера -->
        <UserForm v-if="user" v-model="user" />

        <div v-if="user" class="mt-4">
          <RateEditForm v-if="user?.rate" v-model="user" @save="saveRate" />
          <RateCreateForm v-else @create="createRate" />
        </div>

        <!-- КОМПАКТНЫЙ БЛОК ДЛЯ ССЫЛОК И ШЕРИНГА -->
        <div v-if="user" class="mt-6">
          <div class="text-subtitle-2 mb-3">🔗 Поделиться конфигурацией</div>

          <v-form>
            <!-- Поле 1: Прямое скачивание TOML-файла -->
            <div class="mb-3">
              <div class="text-caption text-medium-emphasis mb-1">Прямая ссылка на скачивание client.toml</div>
              <div class="d-flex gap-2">
                <v-text-field readonly :modelValue="directConfigLink" variant="outlined" density="compact" hide-details class="font-monospace" />
                <v-btn color="primary" variant="tonal" @click="copyDirectLink">
                  Copy
                </v-btn>
              </div>
            </div>

            <!-- Поле 2: Ссылка на страницу с QR-кодом -->
            <div class="mb-3">
              <div class="text-caption text-medium-emphasis mb-1">Ссылка на веб-страницу с QR-кодом</div>
              <div class="d-flex gap-2">
                <v-text-field readonly :modelValue="qrPageLink" variant="outlined" density="compact" hide-details class="font-monospace" />
                <v-btn color="info" variant="tonal" @click="copyQrPageLink">
                  Copy
                </v-btn>
              </div>
            </div>
          </v-form>
        </div>
      </v-card-text>

      <v-divider class="my-4"></v-divider>

      <v-card-actions class="px-0 pb-0 justify-space-between">
        <v-btn color="warning" variant="text" :loading="regenerating" @click="regenerate">
          Regenerate Keys
        </v-btn>

        <div class="d-flex gap-2">
          <v-btn variant="text" @click="close">Close</v-btn>
            <v-btn color="primary" variant="flat" @click="handleSaveUser">Save User</v-btn>
        </div>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.gap-2 { gap: 8px; }
.font-monospace :deep(input) { font-family: monospace; font-size: 13px; }
</style>
