<script setup lang="ts">
import type { User } from '@/models/user'

const user = defineModel<User>('modelValue', {
  required: true,
})
</script>

<template>
  <n-form>
    <!-- UID (editable) -->
    <n-form-item label="UID">
      <n-input v-model:value="user.uid" />
    </n-form-item>

    <!-- Active (editable) -->
    <n-form-item label="Active">
      <n-switch v-model:value="user.is_active" />
    </n-form-item>

    <!-- Static IP (editable) -->
    <n-form-item label="Static IP">
      <n-input v-model:value="user.static_ip" />
    </n-form-item>

    <n-divider />

    <!-- Readonly fields -->

    <n-form-item label="Fingerprint">
      <n-input :value="user.fingerprint" disabled />
    </n-form-item>

    <n-form-item label="Created At">
      <n-input :value="user.created_at" disabled />
    </n-form-item>
  </n-form>
</template>
