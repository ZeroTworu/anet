import { ref, type Ref } from 'vue'
import { AddRate, UpdateRate, DeleteRate } from '@/api/rate'
import type { RateReqRequest } from '@/models/rate'
import type { User } from '@/models/user'
import { useAppMessage } from './useAppMessage'

function extractError(e: unknown, fallback: string): string {
  const err = e as { response?: { data?: unknown }; message?: string }
  if (typeof err?.response?.data === 'string') return err.response.data
  if (err instanceof Error && err.message) return err.message
  return fallback
}

export function useRate(user: Ref<User | null>) {
  const saving = ref(false)
  const message = useAppMessage()

  const saveRate = async () => {
    if (!user.value?.rate) {
      console.error('no rate')
      return
    }
    saving.value = true
    try {
      const updated = await UpdateRate(user.value.rate.id, {
        sessions: user.value.rate.sessions,
        date_end: user.value.rate.date_end,
        traffic_limit: user.value.rate.traffic_limit ?? 0,
        speed_limit: user.value.rate.speed_limit ?? 0,
      })
      user.value.rate = updated
      message.success('Индивидуальный Rate обновлён')
    } catch (e) {
      message.error(extractError(e, 'Не удалось обновить Rate'))
    } finally {
      saving.value = false
    }
  }

  const createRate = async (payload: RateReqRequest) => {
    if (!user.value) return
    saving.value = true
    try {
      const created = await AddRate(user.value.id, {
        sessions: payload.sessions ?? 0,
        date_end: payload.date_end,
        traffic_limit: payload.traffic_limit ?? 0,
        speed_limit: payload.speed_limit ?? 0,
      })
      user.value.rate = created
      message.success('Индивидуальный Rate создан')
    } catch (e) {
      message.error(extractError(e, 'Не удалось создать Rate'))
    } finally {
      saving.value = false
    }
  }

  const deleteRate = async () => {
    if (!user.value?.rate) return
    saving.value = true
    try {
      await DeleteRate(user.value.rate.id)
      user.value.rate = null
      message.success('Индивидуальный Rate удалён — действуют лимиты группы')
    } catch (e) {
      message.error(extractError(e, 'Не удалось удалить Rate'))
    } finally {
      saving.value = false
    }
  }

  return {
    saving,
    saveRate,
    createRate,
    deleteRate,
  }
}
