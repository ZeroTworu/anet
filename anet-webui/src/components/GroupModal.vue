<script setup lang="ts">
import { ref, watch } from 'vue'
import { CreateGroup } from '@/api/groups'
import type { SaveGroupRequest } from '@/models/group'
import { useAppMessage } from '@/composables/useAppMessage'

const show = defineModel<boolean>()

const emit = defineEmits<{
  (e: 'saved'): void
  (e: 'close'): void
}>()

const loading = ref(false)
const message = useAppMessage()

// Поля ввода новой группы
const form = ref({
  name: '',
  traffic_limit_gb: 0,
  speed_limit_mbps: 0,
  sessions_limit: 0,
  duration_days: 0,
})

const resetForm = () => {
  form.value = {
    name: '',
    traffic_limit_gb: 0,
    speed_limit_mbps: 0,
    sessions_limit: 0,
    duration_days: 0,
  }
}

watch(show, (visible) => {
  if (!visible) {
    resetForm()
  }
})

const save = async () => {
  loading.value = true
  try {
    const payload: SaveGroupRequest = {
      name: form.value.name.trim(),
      traffic_limit: (form.value.traffic_limit_gb || 0) * 1024 * 1024 * 1024,
      speed_limit: (form.value.speed_limit_mbps || 0) * 1024,
      sessions_limit: form.value.sessions_limit ?? 0,
      duration_days: form.value.duration_days ?? 0,
    }

    await CreateGroup(payload)
    message.success('Новая группа пользователей создана')
    emit('saved')
    show.value = false
  } catch (e: any) {
    message.error(e?.response?.data || 'Не удалось создать группу')
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
    <v-card>
      <v-card-title class="text-h6 pb-4">
        Создать группу пользователей
      </v-card-title>

      <v-card-text>
        <v-form>
          <!-- Ряд 1: Название группы и лимит сессий -->
          <v-row class="mb-1">
            <v-col cols="12" sm="8">
              <v-text-field
                  v-model="form.name"
                  label="Название группы"
                  placeholder="e.g. Администраторы, VIP, Гости"
                  variant="filled"
                  hide-details
              />
            </v-col>
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.sessions_limit"
                  type="number"
                  label="Сессий (0 - без лимита)"
                  min="0"
                  variant="filled"
                  hide-details
              />
            </v-col>
          </v-row>

          <!-- Ряд 2: Ограничения трафика и скорости -->
          <v-row class="mb-1">
            <v-col cols="12" sm="6">
              <v-text-field
                  v-model.number="form.traffic_limit_gb"
                  type="number"
                  label="Ограничение трафика (ГБ)"
                  placeholder="0 - безлимитный трафик"
                  variant="filled"
                  hide-details
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-text-field
                  v-model.number="form.speed_limit_mbps"
                  type="number"
                  label="Ограничение скорости (Мбит/с)"
                  placeholder="0 - максимальная скорость"
                  variant="filled"
                  hide-details
              />
            </v-col>
          </v-row>

          <!-- Ряд 3: Срок действия доступа -->
          <v-row class="mb-2">
            <v-col cols="12">
              <v-text-field
                  v-model.number="form.duration_days"
                  type="number"
                  label="Срок действия доступа при активации (в днях)"
                  min="0"
                  placeholder="0 - бессрочный доступ"
                  variant="filled"
                  hide-details
              />
            </v-col>
          </v-row>
        </v-form>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
        <v-btn variant="text" @click="close">Отмена</v-btn>
        <v-btn
            color="primary"
            variant="flat"
            :loading="loading"
            :disabled="!form.name.trim() || form.sessions_limit < 0 || form.duration_days < 0"
            @click="save"
        >
          Создать группу
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
