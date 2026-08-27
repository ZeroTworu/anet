<script setup lang="ts">
import { ref } from 'vue'
import { CreateServer } from '@/api/servers'
import type { CreateServerRequest } from '@/models/server'

// Используем дефолтный v-model для управления видимостью окна
const show = defineModel<boolean>()

const emit = defineEmits<{
  (e: 'created'): void
  (e: 'close'): void
}>()

const loading = ref(false)

// Функция для сброса формы к значениям по умолчанию (с учетом портов)
const defaultForm = (): CreateServerRequest => ({
  name: '',
  dsn: 'quic://127.0.0.1:4519',
  public_key: '',
  ssh_user: 'hanyuu',
  is_active: true,
  quic_port: 4519,
  ssh_port: 822,
  vnc_port: 56678,
  websocket_url: 'ws://127.0.0.1:8080/s',
})

const form = ref<CreateServerRequest>(defaultForm())

const handleCreate = async () => {
  loading.value = true
  try {
    await CreateServer(form.value)
    form.value = defaultForm() // Сбрасываем форму после успеха
    emit('created')            // Сообщаем родителю, что надо обновить список
    show.value = false         // Закрываем модалку
  } catch (error) {
    console.error('Ошибка при создании сервера:', error)
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
  <v-dialog v-model="show" @update:model-value="close" max-width="650px">
    <!-- Обертка v-card задаст правильный фон и структуру модального окна -->
    <v-card>
      <v-card-title class="text-h6 pb-4">
        Добавить физический сервер
      </v-card-title>

      <v-card-text>
        <v-form>
          <v-text-field
              v-model="form.name"
              label="Название локации"
              placeholder="e.g. Germany VPS 1"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="form.dsn"
              label="DSN"
              placeholder="quic://host:4519 или wss://host:8080/socket"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="form.public_key"
              label="Публичный ключ сервера (server_pub_key)"
              placeholder="Из утилиты anet-keygen"
              variant="filled"
              class="mb-3"
          />

          <!-- Размещаем порты side-by-side с числовой валидацией -->
          <v-row class="mb-1">
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.quic_port"
                  type="number"
                  label="QUIC Port (UDP)"
                  variant="filled"
                  hide-details
              />
            </v-col>
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.ssh_port"
                  type="number"
                  label="SSH Port (TCP)"
                  variant="filled"
                  hide-details
              />
            </v-col>
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.vnc_port"
                  type="number"
                  label="VNC Port (TCP)"
                  variant="filled"
                  hide-details
              />
            </v-col>
          </v-row>

          <v-text-field
              v-model="form.websocket_url"
              label="WebSocket URL"
              placeholder="ws://127.0.0.1:8080/s"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="form.ssh_user"
              label="Пользователь SSH (ssh_user)"
              placeholder="hanyuu"
              variant="filled"
              class="mb-3"
          />

          <v-switch
              v-model="form.is_active"
              label="Активен (ВКЛ)"
              color="success"
              class="mb-2"
          />
        </v-form>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
        <v-btn variant="text" @click="close">Cancel</v-btn>
        <v-btn color="primary" variant="flat" :loading="loading" @click="handleCreate">
          Add Node
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
