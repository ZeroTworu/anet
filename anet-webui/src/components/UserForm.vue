<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import type { User } from '@/models/user'
import { GetGroups } from '@/api/groups'
import type { UserGroup } from '@/models/group'

const user = defineModel<User>('modelValue', {
  required: true,
})

// Поле нового пароля и флаг сброса пароля
const password = defineModel<string>('password', { default: '' })
const clearPassword = defineModel<boolean>('clearPassword', { default: false })

// Валидность формы наружу (кнопка Create/Save в родительской модалке)
const valid = defineModel<boolean>('valid', { default: false })

// Режим создания: показываем только поля, входящие в CreateUserRequest
const props = defineProps<{
  creating?: boolean
}>()

const showPassword = ref(false)
const availableGroups = ref<UserGroup[]>([])

const groupOptions = computed(() =>
  availableGroups.value.map((group) => ({
    title: `${group.name} (+${group.duration_days} дн.)${group.is_default ? ' [по умолч.]' : ''}`,
    value: group.id,
  })),
)

const uidRules = computed(() => [
  (v: string | null | undefined) => {
    const trimmed = v?.trim() || ''
    if (props.creating && !trimmed) return 'UID обязателен'
    if (trimmed && (trimmed.length < 2 || trimmed.length > 64)) {
      return 'Длина имени должна быть от 2 до 64 символов'
    }
    return true
  },
])

const emailRules = [
  (v: string | null | undefined) => {
    const trimmed = v?.trim() || ''
    if (!trimmed) return true
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed) || 'Некорректный формат Email'
  },
]

const passwordRules = [
  (v: string | null | undefined) => {
    if (!v || clearPassword.value) return true
    return v.length >= 5 || 'Минимум 5 символов'
  },
]

const onToggleClearPassword = (val: boolean | null) => {
  clearPassword.value = Boolean(val)
  if (clearPassword.value) {
    password.value = ''
  }
}

onMounted(async () => {
  try {
    availableGroups.value = await GetGroups()
  } catch (e) {
    console.error('Failed to fetch groups inside form:', e)
  }
})
</script>

<template>
  <v-form v-model="valid" @submit.prevent>
    <!-- UID (editable) -->
    <v-text-field
      v-model="user.uid"
      label="UID"
      :rules="uidRules"
      counter="64"
      class="mb-3"
    />

    <!-- Email для входа в Личный Кабинет -->
    <v-text-field
      v-model="user.email"
      label="Email (Личный Кабинет)"
      placeholder="user@example.com"
      type="email"
      clearable
      :rules="emailRules"
      prepend-inner-icon="mdi-email-outline"
      hint="Очистите поле и сохраните, чтобы отвязать Email"
      persistent-hint
      class="mb-4"
    />

    <!-- Установка / смена пароля -->
    <div class="mb-4">
      <div v-if="!props.creating" class="d-flex align-center justify-space-between mb-2">
        <div class="d-flex align-center ga-2">
          <span class="text-caption text-medium-emphasis">Статус пароля ЛК:</span>
          <v-chip
            size="x-small"
            variant="tonal"
            :color="clearPassword ? 'error' : user.has_password ? 'success' : 'warning'"
          >
            {{ clearPassword ? 'Будет удалён' : user.has_password ? 'Установлен' : 'Не задан' }}
          </v-chip>
        </div>
        <v-checkbox
          v-if="user.has_password"
          :model-value="clearPassword"
          label="Удалить пароль"
          density="compact"
          hide-details
          color="error"
          @update:model-value="onToggleClearPassword"
        />
      </div>

      <v-text-field
        v-model="password"
        :disabled="clearPassword"
        :type="showPassword ? 'text' : 'password'"
        :label="props.creating ? 'Пароль (опционально)' : 'Новый пароль (установить / сменить)'"
        :placeholder="props.creating ? 'Оставьте пустым или задайте пароль' : 'Оставьте пустым, чтобы не менять текущий пароль'"
        :rules="passwordRules"
        prepend-inner-icon="mdi-lock-outline"
        :append-inner-icon="showPassword ? 'mdi-eye-off' : 'mdi-eye'"
        clearable
        autocomplete="new-password"
        @click:append-inner="showPassword = !showPassword"
      />
    </div>

    <!-- Выбор группы (Тарифа) -->
    <v-select
      v-model="user.group_id"
      clearable
      :items="groupOptions"
      label="Группа пользователей"
      placeholder="Выберите группу пользователей"
      class="mb-3"
    />

    <template v-if="!props.creating">
      <!-- Active (editable) -->
      <v-switch v-model="user.is_active" label="Active" color="success" class="mb-2" />
      <!-- Static IP (editable) -->
      <v-text-field
        v-model="user.static_ip"
        label="Static IP"
        placeholder="e.g. 10.0.0.10"
        clearable
        class="mb-3"
      />
    </template>

    <template v-if="!props.creating">
      <v-divider class="my-4" />
      <!-- Readonly fields -->
      <v-row dense>
        <v-col cols="12" sm="6">
          <v-text-field
            :model-value="user.telegram_id ?? '—'"
            label="Telegram ID"
            disabled
            density="compact"
            class="mb-2"
          />
        </v-col>
        <v-col cols="12" sm="6">
          <v-text-field
            :model-value="`${user.balance ?? 0} ₽`"
            label="Баланс ЛК"
            disabled
            density="compact"
            class="mb-2"
          />
        </v-col>
        <v-col cols="12" sm="6">
          <v-text-field
            :model-value="user.activated_at || 'Не активирован'"
            label="Activated At (Smart Activation)"
            disabled
            density="compact"
            class="mb-2"
          />
        </v-col>
        <v-col cols="12" sm="6">
          <v-text-field
            :model-value="user.expires_at || '—'"
            label="Expires At"
            disabled
            density="compact"
            class="mb-2"
          />
        </v-col>
      </v-row>
      <v-text-field :model-value="user.fingerprint" label="Fingerprint" disabled class="mb-3" />
      <v-text-field :model-value="user.created_at" label="Created At" disabled />
    </template>
  </v-form>
</template>
