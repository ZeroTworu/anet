<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { DeleteMailbox, GetMailboxes } from '@/api/mailboxes'
import type { ImapMailbox } from '@/models/mailbox'
import MailboxModal from '@/components/MailboxModal.vue'
import { useAppMessage } from '@/composables/useAppMessage'

const message = useAppMessage()
const mailboxes = ref<ImapMailbox[]>([])
const loading = ref(false)
const search = ref('')

const showModal = ref(false)
const selectedMailbox = ref<ImapMailbox | null>(null)

const headers = [
  { title: 'Хост IMAP', key: 'host', sortable: true },
  { title: 'Порт', key: 'port', sortable: true, align: 'center' as const },
  { title: 'Email (Аккаунт)', key: 'email', sortable: true },
  { title: 'Пароль клиента', key: 'has_client_password', sortable: false, align: 'center' as const },
  { title: 'Пароль сервера', key: 'has_server_password', sortable: false, align: 'center' as const },
  { title: 'Обновлено', key: 'updated_at', sortable: true },
  { title: 'Статус', key: 'is_active', sortable: true, align: 'center' as const },
  { title: 'Действия', key: 'actions', sortable: false, align: 'center' as const },
]

const loadMailboxes = async () => {
  loading.value = true
  try {
    mailboxes.value = await GetMailboxes()
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка загрузки ящиков'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  } finally {
    loading.value = false
  }
}

const openCreate = () => {
  selectedMailbox.value = null
  showModal.value = true
}

const openEdit = (m: ImapMailbox) => {
  selectedMailbox.value = m
  showModal.value = true
}

const removeMailbox = async (id: string) => {
  if (!confirm('Вы уверены, что хотите удалить этот почтовый ящик? Он перестанет использоваться в связанных пулах.')) return
  try {
    await DeleteMailbox(id)
    message.success('Почтовый ящик удален')
    await loadMailboxes()
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка удаления ящика'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
}

onMounted(loadMailboxes)
</script>

<template>
  <v-container fluid class="mailboxes-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-4">
      <v-list-item
        class="px-0"
        subtitle="Справочник служебных учетных записей для защищенного туннелирования трафика через IMAP"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">Почтовые ящики IMAP</h1>
        </template>
      </v-list-item>
    </div>

    <div class="d-flex justify-space-between align-center mb-4">
      <v-text-field
        v-model="search"
        prepend-inner-icon="mdi-magnify"
        label="Поиск по email или хосту..."
        variant="outlined"
        density="compact"
        hide-details
        single-line
        style="width: 280px"
      />
      <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreate">
        + ДОБАВИТЬ ЯЩИК
      </v-btn>
    </div>

    <v-data-table
      :headers="headers"
      :items="mailboxes"
      :search="search"
      :loading="loading"
      :items-per-page="10"
      :items-per-page-options="[10, 20, 50]"
      items-per-page-text="Items per page:"
      loading-text="Загрузка списка почтовых ящиков…"
      no-data-text="Почтовых ящиков пока нет — добавьте первый служебный аккаунт!"
      density="comfortable"
      class="border rounded-lg"
      hover
    >
      <template #item.host="{ item }">
        <code class="font-weight-bold text-primary">{{ item.host }}</code>
      </template>

      <template #item.port="{ item }">
        <v-chip size="small" variant="outlined">{{ item.port }}</v-chip>
      </template>

      <template #item.email="{ item }">
        <span class="font-weight-medium">{{ item.email }}</span>
      </template>

      <template #item.has_client_password="{ item }">
        <v-chip
          size="small"
          :color="item.has_client_password ? 'success' : 'error'"
          variant="tonal"
        >
          {{ item.has_client_password ? 'Зашифрован' : 'Отсутствует' }}
        </v-chip>
      </template>

      <template #item.has_server_password="{ item }">
        <v-chip
          size="small"
          :color="item.has_server_password ? 'info' : 'default'"
          variant="outlined"
        >
          {{ item.has_server_password ? 'Задан' : 'Как у клиента' }}
        </v-chip>
      </template>

      <template #item.updated_at="{ item }">
        <span class="text-caption text-medium-emphasis">{{ item.updated_at }}</span>
      </template>

      <template #item.is_active="{ item }">
        <v-chip :color="item.is_active ? 'success' : 'default'" size="small">
          {{ item.is_active ? 'ACTIVE' : 'OFF' }}
        </v-chip>
      </template>

      <template #item.actions="{ item }">
        <div class="d-flex ga-1 justify-center flex-nowrap">
          <v-btn
            icon="mdi-pencil"
            size="small"
            variant="text"
            title="Редактировать ящик"
            @click="openEdit(item)"
          />
          <v-btn
            icon="mdi-delete"
            size="small"
            variant="text"
            color="error"
            title="Удалить ящик"
            @click="removeMailbox(item.id)"
          />
        </div>
      </template>
    </v-data-table>

    <MailboxModal
      v-model="showModal"
      :mailbox="selectedMailbox"
      @saved="loadMailboxes"
    />
  </v-container>
</template>

<style scoped>
.mailboxes-page {
  padding: 24px;
}
</style>
