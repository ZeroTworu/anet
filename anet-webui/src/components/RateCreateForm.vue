<script setup lang="ts">
import type { RateReqRequest } from '@/models/rate'
import { formatDate } from '@/utils'
import { computed, ref } from 'vue'

defineProps<{
  saving?: boolean
}>()

const emit = defineEmits<{
  (e: 'create', payload: RateReqRequest): void
}>()

const BYTES_IN_GB = 1024 * 1024 * 1024
const KBPS_IN_MBPS = 1024

const form = ref({
  sessions: 0,
  date_end: formatDate(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), 'yyyy-MM-dd-HH:mm'),
  traffic_limit_gb: 0,
  speed_limit_mbps: 0,
})

// Преобразование YYYY-MM-DD-HH:mm <-> YYYY-MM-DDTHH:mm для input type="datetime-local"
const dateEndInput = computed({
  get: () => {
    const val = form.value.date_end || ''
    if (val.length >= 16 && val[10] === '-') {
      return `${val.slice(0, 10)}T${val.slice(11, 16)}`
    }
    return val
  },
  set: (v: string) => {
    if (v && v.includes('T')) {
      form.value.date_end = v.replace('T', '-').slice(0, 16)
    } else {
      form.value.date_end = v
    }
  },
})

const submit = () => {
  emit('create', {
    sessions: Math.max(0, Math.round(Number(form.value.sessions) || 0)),
    date_end: form.value.date_end,
    traffic_limit: Math.max(0, Math.round((Number(form.value.traffic_limit_gb) || 0) * BYTES_IN_GB)),
    speed_limit: Math.max(0, Math.round((Number(form.value.speed_limit_mbps) || 0) * KBPS_IN_MBPS)),
  })
}
</script>

<template>
  <v-divider class="mb-4">Индивидуальный Rate (Создать)</v-divider>
  <v-form @submit.prevent>
    <v-row dense>
      <v-col cols="12" sm="6">
        <v-number-input
          v-model="form.sessions"
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
          v-model.number="form.traffic_limit_gb"
          label="Лимит трафика (ГБ, 0 — безлимит)"
          type="number"
          min="0"
          step="0.5"
          :hint="`${Math.max(0, Math.round((form.traffic_limit_gb || 0) * BYTES_IN_GB))} байт`"
          persistent-hint
          class="mb-2"
        />
      </v-col>
      <v-col cols="12" sm="6">
        <v-text-field
          v-model.number="form.speed_limit_mbps"
          label="Лимит скорости (Мбит/с, 0 — макс)"
          type="number"
          min="0"
          step="1"
          :hint="`${Math.max(0, Math.round((form.speed_limit_mbps || 0) * KBPS_IN_MBPS))} kbps`"
          persistent-hint
          class="mb-2"
        />
      </v-col>
    </v-row>
  </v-form>
  <v-btn color="primary" class="mt-2" :loading="saving" @click="submit">
    Create Rate
  </v-btn>
</template>
