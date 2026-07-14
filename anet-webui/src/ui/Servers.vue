<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { GetServers, CreateServer } from '@/api/servers'
import type { Server, CreateServerRequest } from '@/models/server'

const data = ref<Server[]>([])
const loading = ref(false)
const showCreate = ref(false)
const createLoading = ref(false)

const form = ref<CreateServerRequest>({
  name: '',
  address: '',
  public_key: '',
  quic_port: 4519,
  ssh_port: 822,
  vnc_port: 56678,
  ssh_user: 'hanyuu',
})

const loadServers = async () => {
  loading.value = true
  try {
    data.value = await GetServers()
  } finally {
    loading.value = false
  }
}

const handleCreate = async () => {
  createLoading.value = true
  try {
    await CreateServer(form.value)
    showCreate.value = false
    form.value = {
      name: '',
      address: '',
      public_key: '',
      quic_port: 4519,
      ssh_port: 822,
      vnc_port: 56678,
      ssh_user: 'hanyuu',
    }
    await loadServers()
  } finally {
    createLoading.value = false
  }
}

onMounted(loadServers)
</script>

<template>
  <!-- ЕДИНЫЙ КОРНЕВОЙ ЭЛЕМЕНТ ( divs ) ДЛЯ СТРАНИЦЫ СЕРВЕРОВ -->
  <div style="padding: 24px; max-width: 1200px; margin: 0 auto;">
    <n-space justify="space-between" align="center" style="margin-bottom: 20px;">
      <h2 style="margin: 0; font-weight: 600; font-size: 20px;">VPN Nodes (Servers)</h2>
      <n-button type="primary" @click="showCreate = true"> Add Server </n-button>
    </n-space>

    <n-spin :show="loading">
      <div class="table-container" v-if="data.length">
        <n-table :bordered="true" :single-line="false" class="interactive-table">
          <thead>
          <tr>
            <th>Название</th>
            <th>IP / Домен</th>
            <th>QUIC Port</th>
            <th>SSH Port</th>
            <th>VNC Port</th>
          </tr>
          </thead>
          <tbody>
          <tr v-for="item in data" :key="item.id" class="static-row">
            <td class="name-col">{{ item.name }}</td>
            <td class="addr-col">{{ item.address }}</td>
            <td><n-tag type="success" size="small">{{ item.quic_port || 'Closed' }}</n-tag></td>
            <td><n-tag type="warning" size="small">{{ item.ssh_port || 'Closed' }}</n-tag></td>
            <td><n-tag type="info" size="small">{{ item.vnc_port || 'Closed' }}</n-tag></td>
          </tr>
          </tbody>
        </n-table>
      </div>
      <n-empty v-else description="Серверов пока нет. Добавьте первую ноду!" style="margin-top: 40px;" />
    </n-spin>

    <n-modal v-model:show="showCreate" preset="card" style="width: 650px;" title="Добавить физический сервер">
      <n-form>
        <n-form-item label="Название локации">
          <n-input v-model:value="form.name" placeholder="e.g. Germany VPS 1" />
        </n-form-item>

        <n-form-item label="IP Адрес или Домен">
          <n-input v-model:value="form.address" placeholder="e.g. 127.0.0.1 or vps.example.com" />
        </n-form-item>

        <n-form-item label="Публичный ключ сервера (server_pub_key)">
          <n-input v-model:value="form.public_key" placeholder="Из утилиты anet-keygen" />
        </n-form-item>

        <n-space item-style="width: 175px;">
          <n-form-item label="QUIC Port (UDP)">
            <n-input-number v-model:value="form.quic_port" clearable />
          </n-form-item>

          <n-form-item label="SSH Port (TCP)">
            <n-input-number v-model:value="form.ssh_port" clearable />
          </n-form-item>

          <n-form-item label="VNC Port (TCP)">
            <n-input-number v-model:value="form.vnc_port" clearable />
          </n-form-item>
        </n-space>

        <n-form-item label="Пользователь SSH (ssh_user)">
          <n-input v-model:value="form.ssh_user" placeholder="hanyuu" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showCreate = false">Cancel</n-button>
          <n-button type="primary" :loading="createLoading" @click="handleCreate"> Add Node </n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<style scoped>
.table-container {
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
  border: 1px solid #dcdcdc !important;
  overflow: hidden;
}

.interactive-table :deep(th) {
  background-color: #f5f5f7 !important;
  color: #1a1a1a !important;
  font-weight: 700 !important;
  border-bottom: 2px solid #c5c5c5 !important;
}

.interactive-table :deep(td) {
  border-bottom: 1px solid #dcdcdc !important;
  padding: 16px 20px !important;
}

.static-row:nth-child(even) {
  background-color: #fcfcfc !important;
}

.name-col {
  font-weight: 600 !important;
  color: #1a1a1a !important;
  font-size: 15px !important;
}

.addr-col {
  font-family: 'Fira Code', 'Courier New', Courier, monospace !important;
  color: #4a5568 !important;
}

@media (prefers-color-scheme: dark) {
  .table-container {
    background: #18181c;
    border: 1px solid #333;
  }
  .interactive-table :deep(th) {
    background-color: #26262a !important;
    color: #fff !important;
    border-bottom: 2px solid #444 !important;
  }
  .interactive-table :deep(td) {
    border-bottom: 1px solid #333 !important;
  }
  .static-row:nth-child(even) {
    background-color: #1c1c20 !important;
  }
  .name-col {
    color: #ffffff !important;
  }
  .addr-col {
    color: #cbd5e1 !important;
  }
}
</style>
