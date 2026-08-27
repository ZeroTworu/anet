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
  <v-divider class="mb-4">Rate (Edit)</v-divider>

  <v-form v-if="user.rate">
    <v-number-input
      v-model="user.rate.sessions"
      label="Sessions"
      :min="0"
      class="mb-3"
    />

    <v-text-field
      v-model="user.rate.date_end"
      label="Date End"
      type="datetime-local"
      value-format="yyyy-MM-dd-HH:mm"
    />
  </v-form>

  <v-btn color="primary" class="mt-2" @click="emit('save')"> Update Rate </v-btn>
</template>
