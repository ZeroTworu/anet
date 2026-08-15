<script setup lang="ts">
// Карточка ноды: настройки endpoint, admission-команды и одноразовая выдача
// credential для исходящего control plane соединения.
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useAppMessage } from '@/composables/useAppMessage'
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
  dsn: '',
  public_key: '',
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
const message = useAppMessage()
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
          dsn: val.dsn,
          public_key: val.public_key,
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
  <v-dialog v-model="show" @update:modelValue="close" style="width: 650px;" title="Редактировать физический сервер">
    <v-form>
      <div label="Название локации">
        <v-text-field v-model="form.name" />
      </div>

      <div label="DSN">
        <v-text-field v-model="form.dsn" placeholder="quic://host:4519 или wss://host:8080/socket" />
      </div>

      <div label="Публичный ключ сервера">
        <v-text-field v-model="form.public_key" />
      </div>

      <div label="Пользователь SSH">
        <v-text-field v-model="form.ssh_user" />
      </div>

      <div label="Статус (ВКЛ / ВЫКЛ)">
        <v-switch v-model="form.is_active" />
      </div>

      <v-card v-if="server" size="small" title="Управление подключениями">
        <div vertical>
          <span>
            Фактическое состояние:
            <v-chip
                 :color="server.runtime ? (server.runtime.accepting_connections ? 'success' : 'warning') : 'default'"
                size="small"
            >
              {{ !server.runtime ? 'нет данных' : server.runtime.accepting_connections ? 'принимает новые подключения' : 'новые подключения запрещены' }}
            </v-chip>
          </span>
          <div>
            <v-btn
                type="success"
                ghost
                :loading="commandLoading"
                :disabled="server.runtime?.status !== 'online' || server.runtime?.accepting_connections === true"
                @click="setAdmission(true)"
            >
              Разрешить подключения
            </v-btn>
            <v-btn
                color="warning"
                ghost
                :loading="commandLoading"
                :disabled="server.runtime?.status !== 'online' || server.runtime?.accepting_connections === false"
                @click="setAdmission(false)"
            >
              Запретить новые
            </v-btn>
          </div>
          <span v-if="commandStatus" depth="3">
            Команда: {{ commandStatus === 'pending' ? 'ожидает ноду' : commandStatus === 'running' ? 'выполняется' : commandStatus }}
          </span>
        </div>
      </v-card>

      <v-card v-if="server" size="small" title="Control plane credential" style="margin-top: 12px">
        <div vertical>
          <span>Состояние:
            <v-chip  :color="server.has_control_credential ? 'success' : 'warning'" size="small">
              {{ server.has_control_credential ? 'PROVISIONED' : 'NOT PROVISIONED' }}
            </v-chip>
          </span>
          <span depth="3">
            Credential хранится на панели только в виде SHA-256 хэша. После перевыпуска текущая нода потеряет доступ,
            пока новый token не будет записан в её server.toml.
          </span>
          <div>

              <v-btn tertiary :loading="credentialLoading">Перевыпустить credential</v-btn>

            Текущий credential немедленно перестанет работать. Продолжить?
          </div>
        </div>
      </v-card>
    </v-form>
    <div class="d-flex justify-end ga-4">
      <div justify="end">
        <v-btn @click="close">Cancel</v-btn>
        <v-btn color="primary" :loading="loading" @click="save"> Save </v-btn>
      </div>
    </div>
  </v-dialog>

  <v-dialog
      :model-value="issuedCredential !== null"

      style="width: min(620px, calc(100vw - 32px))"
      title="Новый credential ноды"
      :mask-closable="false"
      @update:modelValue="handleCredentialVisibility"
  >
    <v-alert type="warning" :show-icon="true" style="margin-bottom: 14px">
      Сохраните token сейчас: повторно панель его не покажет.
    </v-alert>
    <div label="node_id">
      <v-text-field :modelValue="issuedCredential?.node_id" readonly />
    </div>
    <div label="control_plane.token">
      <v-text-field :modelValue="issuedCredential?.token" type="password" append-inner-icon="mdi-eye" readonly />
    </div>
    <pre
        v-if="issuedCredential"
        language="toml"
        :code="credentialConfig"
        word-wrap
    />
    <div class="d-flex justify-end ga-4">
      <div justify="end">
        <v-btn @click="copyCredential">Скопировать token</v-btn>
        <v-btn color="primary" @click="issuedCredential = null">Я сохранил</v-btn>
      </div>
    </div>
  </v-dialog>
</template>
