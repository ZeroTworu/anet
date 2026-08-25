<template>
  <v-container class="d-flex align-center justify-center">
    <v-card width="100%" max-width="400" class="pa-6" elevation="8">
      <v-card-title class="text-h5 text-center mb-6">
        Вход в систему
      </v-card-title>

      <v-form @submit.prevent="handleLogin" v-model="isFormValid">
        <v-text-field
            v-model="username"
            label="Имя пользователя"
            variant="outlined"
            prepend-inner-icon="mdi-account"
            :rules="[required]"
            class="mb-4"
        />

        <v-text-field
            v-model="password"
            label="Пароль"
            type="password"
            variant="outlined"
            prepend-inner-icon="mdi-lock"
            :rules="[required]"
            class="mb-6"
        />

        <v-alert
            v-if="errorMessage"
            type="error"
            variant="tonal"
            class="mb-6"
            closable
            @click:close="errorMessage = ''"
        >
          {{ errorMessage }}
        </v-alert>

        <v-btn
            type="submit"
            color="primary"
            size="large"
            block
            :loading="isLoading"
            :disabled="!isFormValid"
        >
          Войти
        </v-btn>
      </v-form>
    </v-card>
  </v-container>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { isAxiosError } from 'axios'
import { login } from '@/api/auth'

const router = useRouter()

const username = ref('')
const password = ref('')
const errorMessage = ref('')
const isLoading = ref(false)
const isFormValid = ref(false)

const required = (value: string) => !!value || 'Это поле обязательно'

async function handleLogin() {
  if (!isFormValid.value) return

  isLoading.value = true
  errorMessage.value = ''

  try {
    const token = await login({
      login: username.value,
      password: password.value,
    })

    localStorage.setItem('token', token)
    await router.push('/overview')
  } catch (err) {
    if (isAxiosError(err) && err.response?.status === 401) {
      errorMessage.value = 'Неверный логин или пароль'
    } else {
      errorMessage.value = 'Ошибка соединения с сервером. Попробуйте позже.'
    }
  } finally {
    isLoading.value = false
  }
}
</script>
