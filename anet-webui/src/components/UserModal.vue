<!-- anet-webui/src/components/UserModal.vue -->
<script setup lang="ts">
import { watch, computed } from 'vue'
import { useMessage } from 'naive-ui'

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

const message = useMessage()

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
  <n-modal
      v-model:show="show"
      @update:show="close()"
      preset="card"
      style="width: min(900px, calc(100vw - 48px)); max-height: calc(100vh - 120px); overflow-y: auto"
  >
    <n-card :bordered="false" size="huge" role="dialog" aria-modal="true">
      <n-spin :show="loading">
        <UserForm v-if="user" v-model="user" />

        <n-button type="primary" @click="handleSaveUser"> Save User </n-button>

        <RateEditForm v-if="user?.rate" v-model="user" @save="saveRate" />
        <RateCreateForm v-else @create="createRate" />

        <!-- КОМПАКТНЫЙ БЛОК ДЛЯ ССЫЛОК И ШЕРИНГА -->
        <n-collapse v-if="user" style="margin-top: 24px;">
          <n-collapse-item title="🔗 Поделиться конфигурацией" name="config-sharing">
            <n-form label-placement="top">

              <!-- Поле 1: Прямое скачивание TOML-файла -->
              <n-form-item label="Прямая ссылка на скачивание client.toml">
                <n-input-group>
                  <n-input readonly :value="directConfigLink" style="font-family: monospace;" />
                  <n-button type="primary" @click="copyDirectLink">
                    Copy
                  </n-button>
                </n-input-group>
              </n-form-item>

              <!-- Поле 2: Ссылка на страницу с QR-кодом -->
              <n-form-item label="Ссылка на веб-страницу с QR-кодом">
                <n-input-group>
                  <n-input readonly :value="qrPageLink" style="font-family: monospace;" />
                  <n-button type="info" @click="copyQrPageLink">
                    Copy
                  </n-button>
                </n-input-group>
              </n-form-item>

            </n-form>
          </n-collapse-item>
        </n-collapse>

        <n-divider />

        <n-space justify="space-between" align="center" style="margin-top: 16px;">
          <n-button type="warning" :loading="regenerating" @click="regenerate">
            Regenerate Keys
          </n-button>
          <n-button @click="close"> Close </n-button>
        </n-space>
      </n-spin>
    </n-card>
  </n-modal>
</template>
