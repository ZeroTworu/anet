<!-- anet-webui/src/components/UserModal.vue -->
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

// 1. Вычисляем прямую ссылку на скачивание client.toml
const directConfigLink = computed(() => {
  if (!user.value) return ''
  return `${window.location.origin}/api/v1/config/${user.value.id}`
})

// 2. Вычисляем ссылку на веб-страницу со стильным QR-кодом
const qrPageLink = computed(() => {
  if (!user.value) return ''
  return `${window.location.origin}/api/v1/config/qr/${user.value.id}`
})

// Универсальная функция копирования, устойчивая к блокировкам HTTP со стороны браузеров
const copyToClipboard = (text: string, successMessage: string) => {
  // Если браузер работает по HTTPS/localhost и современный API доступен
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text)
        .then(() => {
          message.success(successMessage)
        })
        .catch(() => {
          message.error('Failed to copy link.')
        })
  } else {
    // Надежный фолбек для обычного HTTP и IP-адресов
    const textArea = document.createElement('textarea')
    textArea.value = text
    // Прячем элемент вне экрана, чтобы интерфейс не дергался
    textArea.style.position = 'fixed'
    textArea.style.left = '-9999px'
    textArea.style.top = '-9999px'
    document.body.appendChild(textArea)

    textArea.focus()
    textArea.select()

    try {
      const successful = document.execCommand('copy')
      if (successful) {
        message.success(successMessage)
      } else {
        message.error('Failed to copy link.')
      }
    } catch (err) {
      console.error('Fallback copy failed:', err)
      message.error('Failed to copy link.')
    }

    document.body.removeChild(textArea)
  }
}

// Копирование прямой ссылки на конфиг
const copyDirectLink = () => {
  if (!directConfigLink.value) return
  copyToClipboard(directConfigLink.value, 'Прямая ссылка на client.toml скопирована!')
}

// Копирование ссылки на страницу с QR-кодом
const copyQrPageLink = () => {
  if (!qrPageLink.value) return
  copyToClipboard(qrPageLink.value, 'Ссылка на страницу с QR-кодом скопирована!')
}

watch(
    () => props.userId,
    (id) => {
      if (id) {
        loadUser(id)
      }
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
      @update:modelValue="close()"

      style="width: min(900px, calc(100vw - 48px)); max-height: calc(100vh - 120px); overflow-y: auto"
  >
    <v-card :bordered="false" size="huge" role="dialog" aria-modal="true">
      <div class="position-relative">
        <UserForm v-if="user" v-model="user" />

        <v-btn color="primary" @click="handleSaveUser"> Save User </v-btn>

        <RateEditForm v-if="user?.rate" v-model="user" @save="saveRate" />
        <RateCreateForm v-else @create="createRate" />

        <!-- КОМПАКТНЫЙ БЛОК ДЛЯ ССЫЛОК И ШЕРИНГА -->
        <div v-if="user" style="margin-top: 24px;">
          <div title="🔗 Поделиться конфигурацией" name="config-sharing">
            <v-form label-placement="top">

              <!-- Поле 1: Прямое скачивание TOML-файла -->
              <div label="Прямая ссылка на скачивание client.toml">
                <div>
                  <v-text-field readonly :modelValue="directConfigLink" style="font-family: monospace;" />
                  <v-btn color="primary" @click="copyDirectLink">
                    Copy
                  </v-btn>
                </div>
              </div>

              <!-- Поле 2: Ссылка на страницу с QR-кодом -->
              <div label="Ссылка на веб-страницу с QR-кодом">
                <div>
                  <v-text-field readonly :modelValue="qrPageLink" style="font-family: monospace;" />
                  <v-btn color="info" @click="copyQrPageLink">
                    Copy
                  </v-btn>
                </div>
              </div>

            </v-form>
          </div>
        </div>

        <v-divider />

        <div justify="space-between" align="center" style="margin-top: 16px;">
          <v-btn color="warning" :loading="regenerating" @click="regenerate">
            Regenerate Keys
          </v-btn>
          <v-btn @click="close"> Close </v-btn>
        </div>
      </div>
    </v-card>
  </v-dialog>
</template>
