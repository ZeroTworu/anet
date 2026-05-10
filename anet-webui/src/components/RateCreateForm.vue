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
  <n-divider title-placement="left"> Rate (Create) </n-divider>

  <n-form>
    <n-form-item label="Sessions">
      <n-input-number v-model:value="form.sessions" />
    </n-form-item>

    <n-form-item label="Date End">
      <n-date-picker
        v-model:formatted-value="form.date_end"
        type="datetime"
        value-format="yyyy-MM-dd-HH:mm"
      />
    </n-form-item>
  </n-form>

  <n-button type="primary" @click="emit('create', form)"> Create Rate </n-button>
</template>
