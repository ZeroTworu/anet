import { ref } from 'vue'
import { GetUser, UpdateUser, Regenerate } from '@/api/users'
import type { UpdateUserRequest, User } from '@/models/user'

export function useUser() {
  const user = ref<User | null>(null)
  const passwordInput = ref('')
  const clearPasswordFlag = ref(false)
  const loading = ref(false)
  const regenerating = ref(false)

  const loadUser = async (id: string) => {
    loading.value = true
    try {
      user.value = await GetUser(id)
      passwordInput.value = ''
      clearPasswordFlag.value = false
    } finally {
      loading.value = false
    }
  }

  const saveUser = async () => {
    if (!user.value) return

    const emailTrimmed = user.value.email?.trim() || ''
    const payload: UpdateUserRequest = {
      is_active: user.value.is_active,
      static_ip: user.value.static_ip?.trim() ?? '',
      group_id: user.value.group_id || undefined,
      clear_group: !user.value.group_id,
      email: emailTrimmed || undefined,
      clear_email: !emailTrimmed,
    }

    if (user.value.uid?.trim()) {
      payload.uid = user.value.uid.trim()
    }

    if (clearPasswordFlag.value) {
      payload.clear_password = true
    } else if (passwordInput.value) {
      payload.password = passwordInput.value
    }

    const updated = await UpdateUser(user.value.id, payload)
    user.value = updated
    passwordInput.value = ''
    clearPasswordFlag.value = false
  }

  const regenerate = async () => {
    if (!user.value) return
    regenerating.value = true
    try {
      const res = await Regenerate(user.value.id)
      user.value.fingerprint = res.fingerprint
    } finally {
      regenerating.value = false
    }
  }

  return {
    user,
    passwordInput,
    clearPasswordFlag,
    loading,
    regenerating,
    loadUser,
    saveUser,
    regenerate,
  }
}
