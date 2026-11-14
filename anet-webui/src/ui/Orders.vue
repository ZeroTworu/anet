<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { GetAdminOrders, GetAdminProducts } from '@/api/billing'
import { useAppMessage } from '@/composables/useAppMessage'
import type {
  AdminOrder,
  AdminProduct,
  Currency,
  OrderStatus,
} from '@/models/billing'

const message = useAppMessage()

const items = ref<AdminOrder[]>([])
const total = ref(0)
const loading = ref(false)
const statusFilter = ref<OrderStatus | null>(null)
const products = ref<AdminProduct[]>([])

const metadataDialog = ref(false)
const selectedOrder = ref<AdminOrder | null>(null)

const options = ref({
  page: 1,
  itemsPerPage: 20,
})

const statusOptions: { title: string; value: OrderStatus | null }[] = [
  { title: 'Все статусы', value: null },
  { title: 'Pending (Ожидает оплаты)', value: 'Pending' },
  { title: 'Paid (Оплачен)', value: 'Paid' },
  { title: 'Failed (Ошибка)', value: 'Failed' },
  { title: 'Cancelled (Отменён)', value: 'Cancelled' },
  { title: 'Refunded (Возврат)', value: 'Refunded' },
]

const headers = [
  { title: 'Дата создания', key: 'created_at', sortable: false },
  { title: 'ID заказа', key: 'id', sortable: false },
  { title: 'Пользователь', key: 'user_id', sortable: false },
  { title: 'Продукт', key: 'product_id', sortable: false },
  { title: 'Сумма', key: 'amount', sortable: false, align: 'end' as const },
  { title: 'Тип', key: 'is_gift', sortable: false, align: 'center' as const },
  { title: 'Статус', key: 'status', sortable: false, align: 'center' as const },
  { title: 'Метаданные', key: 'metadata', sortable: false, align: 'center' as const },
]

const productMap = computed(() => new Map(products.value.map((p) => [p.id, p])))

const currencySymbol: Record<Currency, string> = {
  Rub: '₽',
  Usd: '$',
  Eur: '€',
  Stars: '⭐',
}

const statusMeta: Record<OrderStatus, { label: string; color: string }> = {
  Pending: { label: 'Pending', color: 'warning' },
  Paid: { label: 'Paid', color: 'success' },
  Failed: { label: 'Failed', color: 'error' },
  Cancelled: { label: 'Cancelled', color: 'default' },
  Refunded: { label: 'Refunded', color: 'info' },
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

const formatTimestamp = (iso: string) => {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString('ru-RU', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

const formatAmount = (amount: number, currency: Currency) => {
  const symbol = currencySymbol[currency] ?? currency
  return `${amount.toLocaleString('ru-RU', { maximumFractionDigits: 2 })} ${symbol}`
}

const loadOrders = async (
  page = options.value.page,
  pageSize = options.value.itemsPerPage,
  status = statusFilter.value,
) => {
  loading.value = true
  try {
    const res = await GetAdminOrders(page, pageSize, status)
    items.value = res.items || []
    total.value = res.total || 0
  } catch (err) {
    message.error(getErrorMessage(err, 'Ошибка загрузки заказов'))
  } finally {
    loading.value = false
  }
}

const handleOptions = (opts: { page: number; itemsPerPage: number }) => {
  options.value.page = opts.page
  options.value.itemsPerPage = opts.itemsPerPage
  loadOrders(opts.page, opts.itemsPerPage, statusFilter.value)
}

watch(statusFilter, (newStatus) => {
  options.value.page = 1
  loadOrders(1, options.value.itemsPerPage, newStatus)
})

const copyText = async (text: string, label: string) => {
  try {
    await navigator.clipboard.writeText(text)
    message.info(`${label} скопирован`)
  } catch {
    message.error('Не удалось скопировать в буфер обмена')
  }
}

const openMetadata = (order: AdminOrder) => {
  selectedOrder.value = order
  metadataDialog.value = true
}

const formattedMetadata = computed(() =>
  selectedOrder.value?.metadata ? JSON.stringify(selectedOrder.value.metadata, null, 2) : '{}',
)

onMounted(async () => {
  try {
    products.value = (await GetAdminProducts()) || []
  } catch {
    products.value = []
  }
})
</script>

<template>
  <v-container fluid class="orders-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-4">
      <v-list-item
        class="px-0"
        subtitle="Журнал заказов пользователей, статусы оплаты и подарочные заказы"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">Orders (Заказы)</h1>
        </template>
      </v-list-item>
    </div>

    <div class="d-flex justify-space-between align-center flex-wrap ga-3 mb-4">
      <v-select
        v-model="statusFilter"
        :items="statusOptions"
        item-title="title"
        item-value="value"
        label="Фильтр по статусу"
        variant="outlined"
        density="compact"
        hide-details
        style="max-width: 280px"
      />
      <v-btn
        variant="tonal"
        prepend-icon="mdi-refresh"
        :loading="loading"
        @click="loadOrders(options.page, options.itemsPerPage, statusFilter)"
      >
        Обновить
      </v-btn>
    </div>

    <v-data-table-server
      v-model:items-per-page="options.itemsPerPage"
      v-model:page="options.page"
      :headers="headers"
      :items="items"
      :items-length="total"
      :loading="loading"
      :items-per-page-options="[10, 20, 50, 100]"
      items-per-page-text="Items per page:"
      loading-text="Загрузка заказов…"
      no-data-text="Заказы не найдены"
      density="comfortable"
      class="border rounded-lg"
      hover
      @update:options="handleOptions"
    >
      <template #item.created_at="{ item }">
        <div>
          <div class="text-body-2">{{ formatTimestamp(item.created_at) }}</div>
          <div class="text-caption text-medium-emphasis">
            Обновлён: {{ formatTimestamp(item.updated_at) }}
          </div>
        </div>
      </template>

      <template #item.id="{ item }">
        <div class="d-flex align-center ga-1">
          <code class="text-caption" :title="item.id">{{ item.id.slice(0, 8) }}…</code>
          <v-btn
            icon="mdi-content-copy"
            size="x-small"
            variant="text"
            title="Скопировать ID заказа"
            @click="copyText(item.id, 'ID заказа')"
          />
        </div>
      </template>

      <template #item.user_id="{ item }">
        <div class="d-flex align-center ga-1">
          <code class="text-caption" :title="item.user_id">{{ item.user_id.slice(0, 8) }}…</code>
          <v-btn
            icon="mdi-content-copy"
            size="x-small"
            variant="text"
            title="Скопировать UUID пользователя"
            @click="copyText(item.user_id, 'UUID пользователя')"
          />
        </div>
      </template>

      <template #item.product_id="{ item }">
        <div v-if="productMap.has(item.product_id)">
          <div class="font-weight-medium">{{ productMap.get(item.product_id)?.name }}</div>
          <code class="text-caption text-medium-emphasis">{{ item.product_id.slice(0, 8) }}…</code>
        </div>
        <code v-else class="text-caption text-medium-emphasis" :title="item.product_id">
          {{ item.product_id }}
        </code>
      </template>

      <template #item.amount="{ item }">
        <span class="font-weight-bold text-no-wrap">{{ formatAmount(item.amount, item.currency) }}</span>
      </template>

      <template #item.is_gift="{ item }">
        <v-chip
          size="small"
          variant="tonal"
          :color="item.is_gift ? 'info' : 'default'"
          :prepend-icon="item.is_gift ? 'mdi-gift-outline' : 'mdi-account-outline'"
        >
          {{ item.is_gift ? 'Подарок' : 'Себе' }}
        </v-chip>
      </template>

      <template #item.status="{ item }">
        <v-chip
          size="small"
          :color="statusMeta[item.status]?.color || 'default'"
        >
          {{ statusMeta[item.status]?.label || item.status }}
        </v-chip>
      </template>

      <template #item.metadata="{ item }">
        <v-btn
          v-if="item.metadata"
          size="x-small"
          variant="tonal"
          color="primary"
          prepend-icon="mdi-code-json"
          @click="openMetadata(item)"
        >
          JSON
        </v-btn>
        <span v-else class="text-caption text-medium-emphasis">—</span>
      </template>
    </v-data-table-server>

    <v-dialog v-model="metadataDialog" max-width="640px">
      <v-card class="rounded-lg">
        <v-card-title class="text-h6 pt-5 px-6 pb-2">
          Metadata заказа {{ selectedOrder?.id.slice(0, 8) }}…
        </v-card-title>
        <v-divider />
        <v-card-text class="pa-6">
          <pre class="json-pre pa-4 rounded border">{{ formattedMetadata }}</pre>
        </v-card-text>
        <v-divider />
        <v-card-actions class="px-6 py-4">
          <v-btn
            variant="tonal"
            prepend-icon="mdi-content-copy"
            @click="copyText(formattedMetadata, 'JSON')"
          >
            Скопировать JSON
          </v-btn>
          <v-spacer />
          <v-btn variant="text" @click="metadataDialog = false">Закрыть</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<style scoped>
.orders-page {
  padding: 24px;
}

.json-pre {
  background: rgba(0, 0, 0, 0.25);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  line-height: 1.5;
  overflow-x: auto;
  max-height: 420px;
}
</style>
