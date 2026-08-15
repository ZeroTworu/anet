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
    router.push('/overview')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <v-card title="Login" style="max-width: 400px; margin: 100px auto">
    <v-form @submit.prevent="submit">
      <div label="Login">
        <v-text-field v-model="username" placeholder="Enter login" />
      </div>

      <div label="Password">
        <v-text-field
          v-model="password"
          type="password"
          append-inner-icon="mdi-eye"
          placeholder="Enter password"
        />
      </div>

      <v-btn color="primary" block :loading="loading" type="submit"> Войти  </v-btn>
    </v-form>
  </v-card>
</template>
