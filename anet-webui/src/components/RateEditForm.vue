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
  <v-divider title-placement="left"> Rate (Edit) </v-divider>

  <v-form v-if="user.rate">
    <div label="Sessions">
      <v-number-input v-model="user.rate.sessions" />
    </div>

    <div label="Date End">
      <v-text-field
        v-model="user.rate.date_end"
        type="datetime-local"
        value-format="yyyy-MM-dd-HH:mm"
      />
    </div>
  </v-form>

  <v-btn color="primary" @click="emit('save')"> Update Rate </v-btn>
</template>
