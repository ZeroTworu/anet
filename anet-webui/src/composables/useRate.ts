import { computed, ref } from 'vue'
import { AddRate, UpdateRate } from '@/api/rate'
import type { User } from '@/models/user'

export function useRate(user: any) {
  const saving = ref(false)

  const saveRate = async () => {
    if (!user.value?.rate) {
      console.log('no rate')
      return
    }
    saving.value = true
    try {
      await UpdateRate(user.value.rate.id, {
        sessions: user.value.rate.sessions,
        date_end: user.value.rate.date_end,
      })
    } finally {
      saving.value = false
    }
  }

  const createRate = async (payload: any) => {
    if (!user.value) return

    saving.value = true
    try {
      await AddRate(user.value.id, payload)
    } finally {
      saving.value = false
    }
  }

  return {
    saving,
    saveRate,
    createRate,
  }
}
