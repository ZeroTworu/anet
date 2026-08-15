<script setup lang="ts">
// Карточка ноды: настройки endpoint, admission-команды и одноразовая выдача
// credential для исходящего control plane соединения.
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useMessage } from 'naive-ui'
import { GetNodeCommandStatus, RotateNodeCredential, SetNodeAdmission, UpdateServer } from '@/api/servers'
import type { Server } from '@/models/server'

const show = defineModel<boolean>('show')

const props = defineProps<{
  server: Server | null
}>()

const emit = defineEmits<{
  (e: 'updated'): void
  (e: 'close'): void
}>()

const form = ref({
  name: '',
  address: '',
  public_key: '',
  quic_port: null as number | null,
  ssh_port: null as number | null,
  vnc_port: null as number | null,
  websocket_url: null as string | null,
  ssh_user: '',
  is_active: true
})

const loading = ref(false)
const commandLoading = ref(false)
const commandStatus = ref<string | null>(null)
const credentialLoading = ref(false)
const issuedCredential = ref<{ node_id: string; token: string } | null>(null)
const credentialConfig = computed(() => issuedCredential.value
  ? `[control_plane]\nnode_id = "${issuedCredential.value.node_id}"\ntoken = "${issuedCredential.value.token}"`
  : '')
const message = useMessage()
let commandAbort = false

const wait = (milliseconds: number) => new Promise(resolve => window.setTimeout(resolve, milliseconds))

const waitForCommand = async (serverId: string, commandId: string) => {
  const deadline = Date.now() + 30_000
  while (!commandAbort && Date.now() < deadline) {
    const command = await GetNodeCommandStatus(serverId, commandId)
    commandStatus.value = command.status
    if (command.status === 'succeeded') return command
    if (command.status === 'failed') throw new Error(command.error || 'Нода не выполнила команду')
    await wait(750)
  }
  throw new Error('Нода не подтвердила выполнение команды за 30 секунд')
}

const setAdmission = async (accepting: boolean) => {
  if (!props.server) return
  commandLoading.value = true
  commandAbort = false
  commandStatus.value = 'pending'
  try {
    const queued = await SetNodeAdmission(props.server.id, accepting)
    await waitForCommand(props.server.id, queued.command_id)
    message.success(accepting ? 'Нода принимает новые подключения' : 'Новые подключения запрещены')
    emit('updated')
  } catch (e) {
    message.error(e instanceof Error ? e.message : 'Не удалось выполнить команду')
  } finally {
    commandLoading.value = false
    commandStatus.value = null
  }
}

onBeforeUnmount(() => { commandAbort = true })

const rotateCredential = async () => {
  if (!props.server) return
  credentialLoading.value = true
  try {
    issuedCredential.value = await RotateNodeCredential(props.server.id)
  } catch (e) {
    message.error(e instanceof Error ? e.message : 'Не удалось выпустить credential')
  } finally {
    credentialLoading.value = false
  }
}

const copyCredential = async () => {
  if (!issuedCredential.value) return
  await navigator.clipboard.writeText(issuedCredential.value.token)
  message.success('Credential скопирован')
}

const handleCredentialVisibility = (value: boolean) => {
  if (!value) issuedCredential.value = null
}

watch(
    () => props.server,
    (val) => {
      if (val) {
        form.value = {
          name: val.name,
          address: val.address,
          public_key: val.public_key,
          quic_port: val.quic_port,
          ssh_port: val.ssh_port,
          vnc_port: val.vnc_port,
          websocket_url: val.websocket_url,
          ssh_user: val.ssh_user || '',
          is_active: val.is_active
        }
      }
    },
    { immediate: true }
)

const save = async () => {
  if (!props.server) return
  loading.value = true
  try {
    await UpdateServer(props.server.id, form.value)
    emit('updated')
    show.value = false
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

const close = () => {
  commandAbort = true
  show.value = false
  emit('close')
}
</script>

<template>
  <n-modal v-model:show="show" @update:show="close" preset="card" style="width: 650px;" title="Редактировать физический сервер">
    <n-form>
      <n-form-item label="Название локации">
        <n-input v-model:value="form.name" />
      </n-form-item>

      <n-form-item label="IP Адрес или Домен">
        <n-input v-model:value="form.address" />
      </n-form-item>

      <n-form-item label="Публичный ключ сервера">
        <n-input v-model:value="form.public_key" />
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

        <n-form-item label="WebSocket URL">
          <n-input v-model:value="form.websocket_url" placeholder="wss://example.com/socket" clearable />
        </n-form-item>
      </n-space>

      <n-form-item label="Пользователь SSH">
        <n-input v-model:value="form.ssh_user" />
      </n-form-item>

      <n-form-item label="Статус (ВКЛ / ВЫКЛ)">
        <n-switch v-model:value="form.is_active" />
      </n-form-item>

      <n-card v-if="server" size="small" title="Управление подключениями">
        <n-space vertical>
          <span>
            Фактическое состояние:
            <n-tag
                :type="server.runtime ? (server.runtime.accepting_connections ? 'success' : 'warning') : 'default'"
                size="small"
            >
              {{ !server.runtime ? 'нет данных' : server.runtime.accepting_connections ? 'принимает новые подключения' : 'новые подключения запрещены' }}
            </n-tag>
          </span>
          <n-space>
            <n-button
                type="success"
                ghost
                :loading="commandLoading"
                :disabled="server.runtime?.status !== 'online' || server.runtime?.accepting_connections === true"
                @click="setAdmission(true)"
            >
              Разрешить подключения
            </n-button>
            <n-button
                type="warning"
                ghost
                :loading="commandLoading"
                :disabled="server.runtime?.status !== 'online' || server.runtime?.accepting_connections === false"
                @click="setAdmission(false)"
            >
              Запретить новые
            </n-button>
          </n-space>
          <n-text v-if="commandStatus" depth="3">
            Команда: {{ commandStatus === 'pending' ? 'ожидает ноду' : commandStatus === 'running' ? 'выполняется' : commandStatus }}
          </n-text>
        </n-space>
      </n-card>

      <n-card v-if="server" size="small" title="Control plane credential" style="margin-top: 12px">
        <n-space vertical>
          <span>Состояние:
            <n-tag :type="server.has_control_credential ? 'success' : 'warning'" size="small">
              {{ server.has_control_credential ? 'PROVISIONED' : 'NOT PROVISIONED' }}
            </n-tag>
          </span>
          <n-text depth="3">
            Credential хранится на панели только в виде SHA-256 хэша. После перевыпуска текущая нода потеряет доступ,
            пока новый token не будет записан в её server.toml.
          </n-text>
          <n-popconfirm
              positive-text="Перевыпустить"
              negative-text="Отмена"
              @positive-click="rotateCredential"
          >
            <template #trigger>
              <n-button tertiary :loading="credentialLoading">Перевыпустить credential</n-button>
            </template>
            Текущий credential немедленно перестанет работать. Продолжить?
          </n-popconfirm>
        </n-space>
      </n-card>
    </n-form>
    <template #footer>
      <n-space justify="end">
        <n-button @click="close">Cancel</n-button>
        <n-button type="primary" :loading="loading" @click="save"> Save </n-button>
      </n-space>
    </template>
  </n-modal>

  <n-modal
      :show="issuedCredential !== null"
      preset="card"
      style="width: min(620px, calc(100vw - 32px))"
      title="Новый credential ноды"
      :mask-closable="false"
      @update:show="handleCredentialVisibility"
  >
    <n-alert type="warning" :show-icon="true" style="margin-bottom: 14px">
      Сохраните token сейчас: повторно панель его не покажет.
    </n-alert>
    <n-form-item label="node_id">
      <n-input :value="issuedCredential?.node_id" readonly />
    </n-form-item>
    <n-form-item label="control_plane.token">
      <n-input :value="issuedCredential?.token" type="password" show-password-on="click" readonly />
    </n-form-item>
    <n-code
        v-if="issuedCredential"
        language="toml"
        :code="credentialConfig"
        word-wrap
    />
    <template #footer>
      <n-space justify="end">
        <n-button @click="copyCredential">Скопировать token</n-button>
        <n-button type="primary" @click="issuedCredential = null">Я сохранил</n-button>
      </n-space>
    </template>
  </n-modal>
</template>
