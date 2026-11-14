<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { CreateAdminProduct, UpdateAdminProduct } from '@/api/billing'
import type {
  AdminProduct,
  CreateProductRequest,
  Currency,
  ProductType,
  UpdateProductRequest,
} from '@/models/billing'
import type { UserGroup } from '@/models/group'
import { useAppMessage } from '@/composables/useAppMessage'

const show = defineModel<boolean>()

const props = defineProps<{
  product: AdminProduct | null
  groups: UserGroup[]
}>()

const emit = defineEmits<{
  (e: 'saved'): void
  (e: 'close'): void
}>()

const message = useAppMessage()

const name = ref('')
const description = ref('')
const price = ref<number>(0)
const currency = ref<Currency>('Rub')
const productType = ref<ProductType>('GroupSubscription')
const targetId = ref<string | null>(null)
const sortOrder = ref<number>(0)
const badge = ref('')
const metadataText = ref('')
const isActive = ref(true)
const loading = ref(false)

const currencyOptions: { title: string; value: Currency }[] = [
  { title: 'RUB (₽)', value: 'Rub' },
  { title: 'USD ($)', value: 'Usd' },
  { title: 'EUR (€)', value: 'Eur' },
  { title: 'Telegram Stars (⭐)', value: 'Stars' },
]

const productTypeOptions: { title: string; value: ProductType }[] = [
  { title: 'Подписка на группу (GroupSubscription)', value: 'GroupSubscription' },
  { title: 'Расширение тарифа (RateExtension)', value: 'RateExtension' },
  { title: 'Доп. функция (Feature)', value: 'Feature' },
]

const groupOptions = computed(() =>
  props.groups.map((g) => ({
    title: g.duration_days > 0 ? `${g.name} (${g.duration_days} дн.)` : `${g.name} (бессрочно)`,
    value: g.id,
  })),
)

const isUuid = (value: string) =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)

const getErrorMessage = (err: unknown, fallback: string): string => {
  if (typeof err === 'object' && err !== null) {
    const e = err as { response?: { data?: unknown }; message?: string }
    const data = e.response?.data
    if (typeof data === 'string' && data.trim()) return data
    if (typeof data === 'object' && data !== null && 'message' in data) {
      return String((data as { message: unknown }).message)
    }
    if (e.message) return e.message
  }
  return fallback
}

const resetForm = (p: AdminProduct | null) => {
  if (p) {
    name.value = p.name
    description.value = p.description
    price.value = p.price
    currency.value = p.currency
    productType.value = p.product_type
    targetId.value = p.target_id
    sortOrder.value = p.sort_order
    badge.value = p.badge ?? ''
    metadataText.value = p.metadata ? JSON.stringify(p.metadata, null, 2) : ''
    isActive.value = p.is_active
  } else {
    name.value = ''
    description.value = ''
    price.value = 0
    currency.value = 'Rub'
    productType.value = 'GroupSubscription'
    targetId.value = null
    sortOrder.value = 0
    badge.value = ''
    metadataText.value = ''
    isActive.value = true
  }
}

watch(
  [() => props.product, () => show.value],
  ([p, isOpen]) => {
    if (isOpen) {
      resetForm(p)
    }
  },
  { immediate: true },
)

const save = async () => {
  const trimmedName = name.value.trim()
  if (!trimmedName) {
    message.error('Укажите название продукта')
    return
  }

  const numericPrice = Number(price.value)
  if (!Number.isFinite(numericPrice) || numericPrice < 0) {
    message.error('Цена должна быть неотрицательным числом')
    return
  }

  const trimmedTarget = targetId.value?.trim() || null
  if (trimmedTarget && !isUuid(trimmedTarget)) {
    message.error('Target ID должен быть корректным UUID')
    return
  }

  let parsedMetadata: Record<string, unknown> | null = null
  const trimmedMeta = metadataText.value.trim()
  if (trimmedMeta) {
    try {
      const parsed: unknown = JSON.parse(trimmedMeta)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        message.error('Metadata должен быть JSON-объектом (например, {"months": 1})')
        return
      }
      parsedMetadata = parsed as Record<string, unknown>
    } catch {
      message.error('Некорректный JSON в поле Metadata')
      return
    }
  }

  const trimmedBadge = badge.value.trim() || null
  const numericSortOrder = Number.isFinite(Number(sortOrder.value))
    ? Math.trunc(Number(sortOrder.value))
    : 0

  loading.value = true
  try {
    if (props.product) {
      const payload: UpdateProductRequest = {
        name: trimmedName,
        description: description.value.trim(),
        price: numericPrice,
        currency: currency.value,
        product_type: productType.value,
        target_id: trimmedTarget,
        sort_order: numericSortOrder,
        badge: trimmedBadge,
        metadata: parsedMetadata,
        is_active: isActive.value,
      }
      await UpdateAdminProduct(props.product.id, payload)
      message.success('Продукт обновлён')
    } else {
      const payload: CreateProductRequest = {
        name: trimmedName,
        description: description.value.trim(),
        price: numericPrice,
        currency: currency.value,
        product_type: productType.value,
        target_id: trimmedTarget,
        sort_order: numericSortOrder,
        badge: trimmedBadge,
        metadata: parsedMetadata,
        is_active: isActive.value,
      }
      await CreateAdminProduct(payload)
      message.success('Продукт создан')
    }
    emit('saved')
    show.value = false
  } catch (err) {
    message.error(getErrorMessage(err, 'Ошибка сохранения продукта'))
  } finally {
    loading.value = false
  }
}

const close = () => {
  show.value = false
  emit('close')
}
</script>

<template>
  <v-dialog
    v-model="show"
    max-width="680px"
    @update:model-value="(val: boolean) => { if (!val) emit('close') }"
  >
    <v-card class="rounded-lg">
      <v-card-title class="text-h6 pt-5 px-6 pb-1">
        {{ product ? 'Редактировать продукт' : 'Новый продукт / тариф' }}
      </v-card-title>
      <v-card-subtitle class="px-6 pb-4 text-caption text-medium-emphasis">
        Позиция витрины биллинга для Личного Кабинета и Telegram Mini App
      </v-card-subtitle>
      <v-divider />

      <v-card-text class="pa-6">
        <v-form @submit.prevent="save">
          <v-row dense>
            <v-col cols="12" sm="8">
              <v-text-field
                v-model="name"
                label="Название продукта"
                placeholder="Например: Pro 30 дней"
                variant="outlined"
                density="compact"
                hide-details="auto"
                class="mb-3"
              />
            </v-col>
            <v-col cols="12" sm="4">
              <v-text-field
                v-model.number="sortOrder"
                type="number"
                label="Порядок (sort_order)"
                variant="outlined"
                density="compact"
                hide-details="auto"
                class="mb-3"
              />
            </v-col>
          </v-row>

          <v-textarea
            v-model="description"
            label="Описание"
            placeholder="Краткое описание условий тарифа для покупателя"
            rows="2"
            auto-grow
            variant="outlined"
            density="compact"
            hide-details="auto"
            class="mb-3"
          />

          <v-row dense>
            <v-col cols="12" sm="6">
              <v-text-field
                v-model.number="price"
                type="number"
                min="0"
                step="0.01"
                label="Цена"
                variant="outlined"
                density="compact"
                hide-details="auto"
                class="mb-3"
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-select
                v-model="currency"
                :items="currencyOptions"
                item-title="title"
                item-value="value"
                label="Валюта"
                variant="outlined"
                density="compact"
                hide-details="auto"
                class="mb-3"
              />
            </v-col>
          </v-row>

          <v-row dense>
            <v-col cols="12" sm="6">
              <v-select
                v-model="productType"
                :items="productTypeOptions"
                item-title="title"
                item-value="value"
                label="Тип продукта"
                variant="outlined"
                density="compact"
                hide-details="auto"
                class="mb-3"
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-text-field
                v-model="badge"
                label="Бейдж (опционально)"
                placeholder="Например: Хит, -20%, VIP"
                clearable
                variant="outlined"
                density="compact"
                hide-details="auto"
                class="mb-3"
                @click:clear="badge = ''"
              />
            </v-col>
          </v-row>

          <v-select
            v-if="productType === 'GroupSubscription'"
            v-model="targetId"
            :items="groupOptions"
            item-title="title"
            item-value="value"
            label="Целевая группа пользователей (target_id)"
            placeholder="Выберите группу для выдачи при оплате"
            clearable
            variant="outlined"
            density="compact"
            hint="При оплате заказа пользователь будет переведён в выбранную группу"
            persistent-hint
            class="mb-3"
          />
          <v-text-field
            v-else
            v-model="targetId"
            label="Target ID (UUID, опционально)"
            placeholder="Опциональный UUID связанной сущности"
            clearable
            variant="outlined"
            density="compact"
            hide-details="auto"
            class="mb-3"
          />

          <v-textarea
            v-model="metadataText"
            label="Metadata JSON (опционально)"
            placeholder='{"months": 1, "highlight": true}'
            rows="3"
            variant="outlined"
            density="compact"
            hide-details="auto"
            class="mb-4 font-monospace"
          />

          <v-switch
            v-model="isActive"
            label="Активен (отображается на витрине пользователей)"
            color="success"
            hide-details
          />
        </v-form>
      </v-card-text>

      <v-divider />
      <v-card-actions class="px-6 py-4">
        <v-spacer />
        <v-btn variant="text" @click="close">Отмена</v-btn>
        <v-btn
          color="primary"
          variant="flat"
          :loading="loading"
          :disabled="!name.trim()"
          @click="save"
        >
          Сохранить
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.font-monospace :deep(textarea) {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
}
</style>
