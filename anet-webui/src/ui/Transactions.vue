<script setup lang="ts">
import { computed, ref } from 'vue'
import { GetAdminTransactions } from '@/api/billing'
import { useAppMessage } from '@/composables/useAppMessage'
import type { AdminTransaction, PaymentSystem } from '@/models/billing'

const message = useAppMessage()

const items = ref<AdminTransaction[]>([])
const total = ref(0)
const loading = ref(false)
const rawDialog = ref(false)
const selectedTx = ref<AdminTransaction | null>(null)

const options = ref({
  page: 1,
  itemsPerPage: 20,
})

const headers = [
  { title: 'Дата создания', key: 'created_at', sortable: false },
  { title: 'Платёжный шлюз', key: 'payment_system', sortable: false },
  { title: 'Внешний ID (external_tx_id)', key: 'external_tx_id', sortable: false },
  { title: 'ID заказа (order_id)', key: 'order_id', sortable: false },
  { title: 'Получено', key: 'amount_received', sortable: false, align: 'end' as const },
  { title: 'Webhook / Payload', key: 'raw_request', sortable: false, align: 'center' as const },
]

const gatewayColor: Record<PaymentSystem, string> = {
  FreeKassa: 'primary',
  Aaio: 'info',
  YooMoney: 'warning',
  TelegramStars: 'success',
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

const loadTransactions = async (
  page = options.value.page,
  pageSize = options.value.itemsPerPage,
) => {
  loading.value = true
  try {
    const res = await GetAdminTransactions(page, pageSize)
    items.value = res.items || []
    total.value = res.total || 0
  } catch (err) {
    message.error(getErrorMessage(err, 'Ошибка загрузки транзакций'))
  } finally {
    loading.value = false
  }
}

const handleOptions = (opts: { page: number; itemsPerPage: number }) => {
  options.value.page = opts.page
  options.value.itemsPerPage = opts.itemsPerPage
  loadTransactions(opts.page, opts.itemsPerPage)
}

const copyText = async (text: string, label: string) => {
  try {
    await navigator.clipboard.writeText(text)
    message.info(`${label} скопирован`)
  } catch {
    message.error('Не удалось скопировать в буфер обмена')
  }
}

const openRaw = (tx: AdminTransaction) => {
  selectedTx.value = tx
  rawDialog.value = true
}

const formattedRaw = computed(() =>
  selectedTx.value ? JSON.stringify(selectedTx.value.raw_request, null, 2) : '{}',
)
</script>

<template>
  <v-container fluid class="transactions-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-4">
      <v-list-item
        class="px-0"
        subtitle="Аудит входящих платёжных транзакций и сырых уведомлений от шлюзов"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">Transactions (Транзакции)</h1>
        </template>
      </v-list-item>
      <v-btn
        variant="tonal"
        prepend-icon="mdi-refresh"
        :loading="loading"
        @click="loadTransactions(options.page, options.itemsPerPage)"
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
      loading-text="Загрузка транзакций…"
      no-data-text="Транзакции не найдены"
      density="comfortable"
      class="border rounded-lg"
      hover
      @update:options="handleOptions"
    >
      <template #item.created_at="{ item }">
        <span class="text-body-2">{{ formatTimestamp(item.created_at) }}</span>
      </template>

      <template #item.payment_system="{ item }">
        <v-chip
          size="small"
          variant="tonal"
          :color="gatewayColor[item.payment_system] || 'default'"
        >
          {{ item.payment_system }}
        </v-chip>
      </template>

      <template #item.external_tx_id="{ item }">
        <div class="d-flex align-center ga-1">
          <code class="text-caption">{{ item.external_tx_id }}</code>
          <v-btn
            icon="mdi-content-copy"
            size="x-small"
            variant="text"
            title="Скопировать внешний ID транзакции"
            @click="copyText(item.external_tx_id, 'External TX ID')"
          />
        </div>
      </template>

      <template #item.order_id="{ item }">
        <div v-if="item.order_id" class="d-flex align-center ga-1">
          <code class="text-caption" :title="item.order_id">{{ item.order_id.slice(0, 8) }}…</code>
          <v-btn
            icon="mdi-content-copy"
            size="x-small"
            variant="text"
            title="Скопировать ID заказа"
            @click="copyText(item.order_id, 'ID заказа')"
          />
        </div>
        <span v-else class="text-caption text-medium-emphasis">—</span>
      </template>

      <template #item.amount_received="{ item }">
        <span class="font-weight-bold text-no-wrap">
          {{ item.amount_received.toLocaleString('ru-RU', { maximumFractionDigits: 2 }) }}
        </span>
      </template>

      <template #item.raw_request="{ item }">
        <v-btn
          size="x-small"
          variant="tonal"
          color="primary"
          prepend-icon="mdi-code-json"
          @click="openRaw(item)"
        >
          JSON
        </v-btn>
      </template>
    </v-data-table-server>

    <v-dialog v-model="rawDialog" max-width="720px">
      <v-card class="rounded-lg">
        <v-card-title class="text-h6 pt-5 px-6 pb-2">
          Raw Request — {{ selectedTx?.payment_system }} ({{ selectedTx?.external_tx_id }})
        </v-card-title>
        <v-divider />
        <v-card-text class="pa-6">
          <pre class="json-pre pa-4 rounded border">{{ formattedRaw }}</pre>
        </v-card-text>
        <v-divider />
        <v-card-actions class="px-6 py-4">
          <v-btn
            variant="tonal"
            prepend-icon="mdi-content-copy"
            @click="copyText(formattedRaw, 'JSON')"
          >
            Скопировать JSON
          </v-btn>
          <v-spacer />
          <v-btn variant="text" @click="rawDialog = false">Закрыть</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<style scoped>
.transactions-page {
  padding: 24px;
}

.json-pre {
  background: rgba(0, 0, 0, 0.25);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  line-height: 1.5;
  overflow-x: auto;
  max-height: 460px;
}
</style>
