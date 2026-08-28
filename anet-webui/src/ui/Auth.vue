<template>
  <v-container fluid class="fill-height d-flex align-center justify-center" style="min-height: 100vh; background-color: #0c0e0d;">
    <v-card width="100%" max-width="400" class="pa-8" rounded="xl" border elevation="12">
      <!-- Брендированная шапка входа -->
      <div class="text-center mb-8">
        <v-avatar color="primary" size="56" class="mb-3 text-h5 font-weight-bold" style="color: #fff !important;">
          A
        </v-avatar>
        <h1 class="text-h5 font-weight-bold text-primary" style="font-family: monospace; letter-spacing: 1.5px; text-transform: uppercase;">
          ANet VPN
        </h1>
        <p class="text-caption text-medium-emphasis mt-1">
          Control Plane Management Panel
        </p>
      </div>

      <v-form v-model="isFormValid" @submit.prevent="handleLogin">
        <!-- Поле ввода логина -->
        <v-text-field
            v-model="username"
            label="Имя пользователя"
            prepend-inner-icon="mdi-account-outline"
            :rules="[required]"
            clearable
            class="mb-4"
        />

        <!-- Поле ввода пароля с переключателем видимости -->
        <v-text-field
            v-model="password"
            label="Пароль"
            :type="showPassword ? 'text' : 'password'"
            prepend-inner-icon="mdi-lock-outline"
            :append-inner-icon="showPassword ? 'mdi-eye-off-outline' : 'mdi-eye-outline'"
            :rules="[required]"
            @click:append-inner="showPassword = !showPassword"
            class="mb-6"
        />

        <!-- Оповещение об ошибке -->
        <v-alert
            v-if="errorMessage"
            type="error"
            variant="tonal"
            density="comfortable"
            closable
            class="mb-6"
            @click:close="errorMessage = ''"
        >
          {{ errorMessage }}
        </v-alert>

        <!-- Кнопка входа -->
        <v-btn
            type="submit"
            color="primary"
            size="large"
            block
            flat
            :loading="isLoading"
            :disabled="!isFormValid"
            style="text-transform: none; font-weight: 600;"
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
const showPassword = ref(false)

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