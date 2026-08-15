import { ref } from 'vue'
import { GetUser, UpdateUser, Regenerate } from '@/api/users'
import type { User } from '@/models/user'

export function useUser() {
  const user = ref<User | null>(null)
  const loading = ref(false)
  const regenerating = ref(false)

  const loadUser = async (id: string) => {
    loading.value = true
    try {
      user.value = await GetUser(id)
    } finally {
      loading.value = false
    }
  }

  const saveUser = async () => {
    if (!user.value) return

    await UpdateUser(user.value.id, {
      uid: user.value.uid,
      is_active: user.value.is_active,
      static_ip: user.value.static_ip,
      server_ids: user.value.server_ids || [],
      pool_ids: user.value.pool_ids || [],
      route_map_id: user.value.route_map_id || undefined,
      clear_route_map: !user.value.route_map_id,
    })
  }

  const regenerate = async () => {
    if (!user.value) return

    regenerating.value = true
    try {
      await Regenerate(user.value.id)
    } finally {
      regenerating.value = false
    }
  }

  return {
    user,
    loading,
    regenerating,
    loadUser,
    saveUser,
    regenerate,
  }
}
