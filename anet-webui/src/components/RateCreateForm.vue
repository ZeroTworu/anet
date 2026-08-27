<script setup lang="ts">
import type { RateReqRequest } from '@/models/rate'
import { formatDate } from '@/utils'
import { ref } from 'vue'

const emit = defineEmits<{
  (e: 'create', payload: RateReqRequest): void
}>()

const form = ref<RateReqRequest>({
  sessions: 0,
  date_end: formatDate(new Date(), 'yyyy-MM-dd-HH:mm'),
})
</script>

<template>
  <v-divider class="mb-4">Rate (Create)</v-divider>

  <v-form>
    <v-number-input
      v-model="form.sessions"
      label="Sessions"
      :min="0"
      class="mb-3"
    />

    <v-text-field
      v-model="form.date_end"
      label="Date End"
      type="datetime-local"
      value-format="yyyy-MM-dd-HH:mm"
    />
  </v-form>

  <v-btn color="primary" class="mt-2" @click="emit('create', form)"> Create Rate </v-btn>
</template>
