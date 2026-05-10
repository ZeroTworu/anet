<script setup lang="ts">
import type { User } from '@/models/user'

const user = defineModel<User>('modelValue', {
  required: true,
})

const emit = defineEmits<{
  (e: 'save'): void
}>()
</script>

<template>
  <n-divider title-placement="left"> Rate (Edit) </n-divider>

  <n-form v-if="user.rate">
    <n-form-item label="Sessions">
      <n-input-number v-model:value="user.rate.sessions" />
    </n-form-item>

    <n-form-item label="Date End">
      <n-date-picker
        v-model:formatted-value="user.rate.date_end"
        type="datetime"
        value-format="yyyy-MM-dd-HH:mm"
      />
    </n-form-item>
  </n-form>

  <n-button type="primary" @click="emit('save')"> Update Rate </n-button>
</template>
