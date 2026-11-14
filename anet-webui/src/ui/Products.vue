<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { DeleteAdminProduct, GetAdminProducts } from '@/api/billing'
import { GetGroups } from '@/api/groups'
import ProductModal from '@/components/ProductModal.vue'
import { useAppMessage } from '@/composables/useAppMessage'
import type { AdminProduct, Currency, ProductType } from '@/models/billing'
import type { UserGroup } from '@/models/group'

const message = useAppMessage()

const products = ref<AdminProduct[]>([])
const groups = ref<UserGroup[]>([])
const loading = ref(false)
const search = ref('')
const statusFilter = ref<'all' | 'active' | 'inactive'>('all')
const showModal = ref(false)
const selectedProduct = ref<AdminProduct | null>(null)

const headers = [
  { title: '#', key: 'sort_order', sortable: true, width: '72px' },
  { title: 'Название', key: 'name', sortable: true },
  { title: 'Тип', key: 'product_type', sortable: true },
  { title: 'Привязка (Target)', key: 'target_id', sortable: false },
  { title: 'Цена', key: 'price', sortable: true, align: 'end' as const },
  { title: 'Статус', key: 'is_active', sortable: true, align: 'center' as const },
  { title: 'Действия', key: 'actions', sortable: false, align: 'center' as const },
]

const groupMap = computed(() => new Map(groups.value.map((g) => [g.id, g])))

const filteredProducts = computed(() => {
  if (statusFilter.value === 'active') return products.value.filter((p) => p.is_active)
  if (statusFilter.value === 'inactive') return products.value.filter((p) => !p.is_active)
  return products.value
})

const currencySymbol: Record<Currency, string> = {
  Rub: '₽',
  Usd: '$',
  Eur: '€',
  Stars: '⭐',
}

const productTypeMeta: Record<ProductType, { label: string; color: string }> = {
  GroupSubscription: { label: 'Подписка на группу', color: 'primary' },
  RateExtension: { label: 'Расширение тарифа', color: 'info' },
  Feature: { label: 'Доп. функция', color: 'warning' },
}

const formatPrice = (price: number, currency: Currency) => {
  const symbol = currencySymbol[currency] ?? currency
  return `${price.toLocaleString('ru-RU', { maximumFractionDigits: 2 })} ${symbol}`
}

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

const load = async () => {
  loading.value = true
  try {
    const [prodRes, groupRes] = await Promise.all([
      GetAdminProducts(),
      GetGroups().catch(() => [] as UserGroup[]),
    ])
    products.value = prodRes || []
    groups.value = groupRes || []
  } catch (err) {
    message.error(getErrorMessage(err, 'Ошибка загрузки продуктов'))
  } finally {
    loading.value = false
  }
}

const openCreate = () => {
  selectedProduct.value = null
  showModal.value = true
}

const openEdit = (p: AdminProduct) => {
  selectedProduct.value = p
  showModal.value = true
}

const removeProduct = async (p: AdminProduct) => {
  if (!confirm(`Удалить продукт «${p.name}»? Существующие заказы сохранят product_id, но товар пропадёт с витрины.`)) {
    return
  }
  try {
    await DeleteAdminProduct(p.id)
    message.success('Продукт удалён')
    await load()
  } catch (err) {
    message.error(getErrorMessage(err, 'Ошибка удаления продукта'))
  }
}

const copyId = async (id: string) => {
  try {
    await navigator.clipboard.writeText(id)
    message.info('UUID скопирован')
  } catch {
    message.error('Не удалось скопировать в буфер обмена')
  }
}

onMounted(load)
</script>

<template>
  <v-container fluid class="products-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-4">
      <v-list-item
        class="px-0"
        subtitle="Управление витриной подписок, тарифов и дополнительных услуг биллинга"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">Products (Продукты и тарифы)</h1>
        </template>
      </v-list-item>
    </div>

    <div class="d-flex justify-space-between align-center flex-wrap ga-3 mb-4">
      <div class="d-flex align-center flex-wrap ga-3 flex-grow-1">
        <v-text-field
          v-model="search"
          prepend-inner-icon="mdi-magnify"
          label="Поиск по названию, описанию или бейджу..."
          variant="outlined"
          density="compact"
          hide-details
          single-line
          style="max-width: 340px"
        />
        <v-select
          v-model="statusFilter"
          :items="[
            { title: 'Все статусы', value: 'all' },
            { title: 'Только активные', value: 'active' },
            { title: 'Только скрытые', value: 'inactive' },
          ]"
          item-title="title"
          item-value="value"
          variant="outlined"
          density="compact"
          hide-details
          style="max-width: 210px"
        />
      </div>
      <div class="d-flex align-center ga-2">
        <v-btn variant="tonal" prepend-icon="mdi-refresh" :loading="loading" @click="load">
          Обновить
        </v-btn>
        <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreate">
          + ДОБАВИТЬ ПРОДУКТ
        </v-btn>
      </div>
    </div>

    <v-data-table
      :headers="headers"
      :items="filteredProducts"
      :search="search"
      :loading="loading"
      :items-per-page="20"
      :items-per-page-options="[10, 20, 50]"
      items-per-page-text="Items per page:"
      loading-text="Загрузка списка продуктов…"
      no-data-text="Продуктов пока нет — добавьте первый тариф!"
      density="comfortable"
      class="border rounded-lg"
      hover
      @click:row="(_: unknown, data: { item: AdminProduct }) => openEdit(data.item)"
    >
      <template #item.sort_order="{ item }">
        <span class="text-caption font-weight-medium text-medium-emphasis">#{{ item.sort_order }}</span>
      </template>

      <template #item.name="{ item }">
        <div class="py-1">
          <div class="d-flex align-center ga-2 flex-wrap">
            <span class="font-weight-bold">{{ item.name }}</span>
            <v-chip v-if="item.badge" size="x-small" color="warning" variant="tonal">
              {{ item.badge }}
            </v-chip>
          </div>
          <div v-if="item.description" class="text-caption text-medium-emphasis text-truncate" style="max-width: 380px">
            {{ item.description }}
          </div>
        </div>
      </template>

      <template #item.product_type="{ item }">
        <v-chip
          size="small"
          variant="tonal"
          :color="productTypeMeta[item.product_type]?.color || 'default'"
        >
          {{ productTypeMeta[item.product_type]?.label || item.product_type }}
        </v-chip>
      </template>

      <template #item.target_id="{ item }">
        <template v-if="item.target_id">
          <v-chip
            v-if="groupMap.has(item.target_id)"
            size="small"
            variant="tonal"
            color="secondary"
            prepend-icon="mdi-wallet-membership"
          >
            {{ groupMap.get(item.target_id)?.name }}
          </v-chip>
          <code v-else class="text-caption text-medium-emphasis">{{ item.target_id.slice(0, 8) }}…</code>
        </template>
        <span v-else class="text-caption text-medium-emphasis">—</span>
      </template>

      <template #item.price="{ item }">
        <span class="font-weight-bold text-no-wrap">{{ formatPrice(item.price, item.currency) }}</span>
      </template>

      <template #item.is_active="{ item }">
        <v-chip :color="item.is_active ? 'success' : 'default'" size="small">
          {{ item.is_active ? 'ACTIVE' : 'HIDDEN' }}
        </v-chip>
      </template>

      <template #item.actions="{ item }">
        <div class="d-flex ga-1 justify-center flex-nowrap" @click.stop>
          <v-btn
            icon="mdi-content-copy"
            size="small"
            variant="text"
            title="Скопировать UUID продукта"
            @click="copyId(item.id)"
          />
          <v-btn
            icon="mdi-pencil"
            size="small"
            variant="text"
            title="Редактировать продукт"
            @click="openEdit(item)"
          />
          <v-btn
            icon="mdi-delete"
            size="small"
            variant="text"
            color="error"
            title="Удалить продукт"
            @click="removeProduct(item)"
          />
        </div>
      </template>
    </v-data-table>

    <ProductModal
      v-model="showModal"
      :product="selectedProduct"
      :groups="groups"
      @saved="load"
    />
  </v-container>
</template>

<style scoped>
.products-page {
  padding: 24px;
}
</style>
