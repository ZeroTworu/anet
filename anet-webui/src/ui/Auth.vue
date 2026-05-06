<script setup lang="ts">
import { ref } from 'vue'
import { login } from '@/api/auth'
import router from '@/router'

const username = ref('')
const password = ref('')

const submit = async () => {
  const token = await login({
    login: username.value,
    password: password.value
  })

  localStorage.setItem('token', token)
  router.push('/users')
}

</script>

<template>
  <form @submit.prevent="submit">
    <div>
      <label>Email</label>
      <input v-model="username" required />
    </div>

    <div>
      <label>Password</label>
      <input v-model="password" type="password" required />
    </div>

    <button type="submit">Login</button>
  </form>
</template>

<style scoped></style>
