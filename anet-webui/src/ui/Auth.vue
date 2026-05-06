<script setup lang="ts">
import { ref } from 'vue'
import { login } from '@/api/auth'
import router from '@/router'

const username = ref('')
const password = ref('')
const loading = ref(false)

const submit = async () => {
  loading.value = true

  try {
    const token = await login({
      login: username.value,
      password: password.value,
    })

    localStorage.setItem('token', token)
    router.push('/users')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <n-card title="Login" style="max-width: 400px; margin: 100px auto;">
    <n-form @submit.prevent="submit">

      <n-form-item label="Login">
        <n-input v-model:value="username" placeholder="Enter login" />
      </n-form-item>

      <n-form-item label="Password">
        <n-input
          v-model:value="password"
          type="password"
          show-password-on="click"
          placeholder="Enter password"
        />
      </n-form-item>

      <n-button
        type="primary"
        block
        :loading="loading"
        attr-type="submit"
      >
        Login
      </n-button>

    </n-form>
  </n-card>
</template>