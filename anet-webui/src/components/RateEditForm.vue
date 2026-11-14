<script setup lang="ts">
import type { User } from '@/models/user'
import { computed } from 'vue'

defineProps<{
  saving?: boolean
}>()

const user = defineModel<User>('modelValue', {
  required: true,
})

const emit = defineEmits<{
  (e: 'save'): void
  (e: 'delete'): void
}>()

const BYTES_IN_GB = 1024 * 1024 * 1024
const KBPS_IN_MBPS = 1024

// Преобразование YYYY-MM-DD-HH:mm <-> YYYY-MM-DDTHH:mm для input type="datetime-local"
const dateEndInput = computed({
  get: () => {
    const val = user.value.rate?.date_end || ''
    if (val.length >= 16 && val[10] === '-') {
      return `${val.slice(0, 10)}T${val.slice(11, 16)}`
    }
    return val
  },
  set: (v: string) => {
    if (!user.value.rate) return
    if (v && v.includes('T')) {
      user.value.rate.date_end = v.replace('T', '-').slice(0, 16)
    } else {
      user.value.rate.date_end = v
    }
  },
})

const trafficLimitGb = computed({
  get: () => {
    const bytes = user.value.rate?.traffic_limit ?? 0
    if (!bytes) return 0
    return Number((bytes / BYTES_IN_GB).toFixed(2))
  },
  set: (gb: number) => {
    if (!user.value.rate) return
    user.value.rate.traffic_limit = Math.max(0, Math.round((Number(gb) || 0) * BYTES_IN_GB))
  },
})

const speedLimitMbps = computed({
  get: () => {
    const kbps = user.value.rate?.speed_limit ?? 0
    if (!kbps) return 0
    return Number((kbps / KBPS_IN_MBPS).toFixed(2))
  },
  set: (mbps: number) => {
    if (!user.value.rate) return
    user.value.rate.speed_limit = Math.max(0, Math.round((Number(mbps) || 0) * KBPS_IN_MBPS))
  },
})
</script>

<template>
  <v-divider class="mb-4">Индивидуальный Rate (Редактировать)</v-divider>
  <v-form v-if="user.rate" @submit.prevent>
    <v-row dense>
      <v-col cols="12" sm="6">
        <v-number-input
          v-model="user.rate.sessions"
          label="Сессий (0 — безлимит)"
          :min="0"
          class="mb-2"
        />
      </v-col>
      <v-col cols="12" sm="6">
        <v-text-field
          v-model="dateEndInput"
          label="Date End (Дата окончания)"
          type="datetime-local"
          class="mb-2"
        />
      </v-col>
      <v-col cols="12" sm="6">
        <v-text-field
          v-model.number="trafficLimitGb"
          label="Лимит трафика (ГБ, 0 — безлимит)"
          type="number"
          min="0"
          step="0.5"
          :hint="`${user.rate.traffic_limit ?? 0} байт`"
          persistent-hint
          class="mb-2"
        />
      </v-col>
      <v-col cols="12" sm="6">
        <v-text-field
          v-model.number="speedLimitMbps"
          label="Лимит скорости (Мбит/с, 0 — макс)"
          type="number"
          min="0"
          step="1"
          :hint="`${user.rate.speed_limit ?? 0} kbps`"
          persistent-hint
          class="mb-2"
        />
      </v-col>
    </v-row>
  </v-form>
  <div class="d-flex flex-wrap ga-2 mt-2">
    <v-btn color="primary" :loading="saving" @click="emit('save')">
      Update Rate
    </v-btn>
    <v-btn
      color="error"
      variant="tonal"
      prepend-icon="mdi-delete-outline"
      :loading="saving"
      @click="emit('delete')"
    >
      Удалить Rate (на лимиты группы)
    </v-btn>
  </div>
</template>
