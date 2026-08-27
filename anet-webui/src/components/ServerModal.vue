<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useAppMessage } from '@/composables/useAppMessage'
import { GetNodeCommandStatus, RotateNodeCredential, SetNodeAdmission, UpdateServer } from '@/api/servers'
import type { Server } from '@/models/server'

// ИСПРАВЛЕНО: Убрано 'show', теперь ловит дефолтный v-model из родителя
const show = defineModel<boolean>()

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
  <!-- Основная модалка редактирования -->
  <v-dialog v-model="show" @update:model-value="close" max-width="650px">
    <v-card>
      <v-card-title class="text-h6 pb-4">Редактировать физический сервер</v-card-title>

      <v-card-text>
        <v-form>
          <v-text-field v-model="form.name" label="Название локации" variant="filled" class="mb-3" />
          <v-text-field v-model="form.dsn" label="DSN" placeholder="quic://host:4519 или wss://host:8080/socket" variant="filled" class="mb-3" />
          <v-text-field v-model="form.public_key" label="Публичный ключ сервера" variant="filled" class="mb-3" />
          <v-text-field v-model="form.ssh_user" label="Пользователь SSH" variant="filled" class="mb-3" />

          <v-switch v-model="form.is_active" label="Статус (ВКЛ / ВЫКЛ)" color="success" class="mb-4" />

          <!-- Блок управления подключениями -->
          <v-card v-if="server" variant="outlined" class="mb-4 pa-4">
            <div class="text-subtitle-1 font-weight-bold mb-2">Управление подключениями</div>
            <div class="mb-4">
              Фактическое состояние:
              <v-chip
                  :color="server.runtime ? (server.runtime.accepting_connections ? 'success' : 'warning') : 'default'"
                  size="small"
                  class="ml-2"
              >
                {{ !server.runtime ? 'нет данных' : server.runtime.accepting_connections ? 'принимает новые подключения' : 'новые подключения запрещены' }}
              </v-chip>
            </div>

            <div class="d-flex ga-2 mb-2">
              <v-btn
                  color="success"
                  variant="outlined"
                  :loading="commandLoading"
                  :disabled="server.runtime?.status !== 'online' || server.runtime?.accepting_connections === true"
                  @click="setAdmission(true)"
              >
                Разрешить
              </v-btn>
              <v-btn
                  color="warning"
                  variant="outlined"
                  :loading="commandLoading"
                  :disabled="server.runtime?.status !== 'online' || server.runtime?.accepting_connections === false"
                  @click="setAdmission(false)"
              >
                Запретить
              </v-btn>
            </div>
            <div v-if="commandStatus" class="text-caption text-medium-emphasis mt-2">
              Команда: {{ commandStatus === 'pending' ? 'ожидает ноду' : commandStatus === 'running' ? 'выполняется' : commandStatus }}
            </div>
          </v-card>

          <!-- Блок Control plane credential -->
          <v-card v-if="server" variant="outlined" class="pa-4">
            <div class="text-subtitle-1 font-weight-bold mb-2">Control plane credential</div>
            <div class="mb-2">
              Состояние:
              <v-chip :color="server.has_control_credential ? 'success' : 'warning'" size="small" class="ml-2">
                {{ server.has_control_credential ? 'PROVISIONED' : 'NOT PROVISIONED' }}
              </v-chip>
            </div>
            <div class="text-caption text-medium-emphasis mb-4">
              Credential хранится на панели только в виде SHA-256 хэша. После перевыпуска текущая нода потеряет доступ, пока новый token не будет записан в её config.
            </div>

            <div class="d-flex align-center">
              <v-btn variant="tonal" color="error" :loading="credentialLoading" @click="rotateCredential" class="mr-4">
                Перевыпустить credential
              </v-btn>
              <span class="text-caption text-error">Текущий токен сразу сбросится!</span>
            </div>
          </v-card>
        </v-form>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
        <v-btn variant="text" @click="close">Отмена</v-btn>
        <v-btn color="primary" variant="flat" :loading="loading" @click="save">Сохранить</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <!-- Модалка выдачи нового Credential -->
  <v-dialog
      :model-value="issuedCredential !== null"
      max-width="620px"
      persistent
      @update:model-value="handleCredentialVisibility"
  >
    <v-card>
      <v-card-title class="text-h6 pb-4">Новый credential ноды</v-card-title>

      <v-card-text>
        <v-alert type="warning" variant="tonal" class="mb-4">
          Сохраните token сейчас: повторно панель его не покажет.
        </v-alert>

        <v-text-field :model-value="issuedCredential?.node_id" label="node_id" readonly variant="filled" class="mb-3" />

        <v-text-field
            :model-value="issuedCredential?.token"
            label="control_plane.token"
            type="text"
            readonly
            variant="filled"
            class="mb-3"
        />

        <v-sheet v-if="issuedCredential" color="surface-variant" rounded="lg" border class="pa-4">
          <pre class="credential-pre">{{ credentialConfig }}</pre>
        </v-sheet>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
        <v-btn variant="outlined" @click="copyCredential">Скопировать токен</v-btn>
        <v-btn color="primary" variant="flat" @click="issuedCredential = null">Я сохранил</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.credential-pre {
  margin: 0;
  white-space: pre-wrap;
  font-family: 'Fira Code', monospace;
  font-size: 13px;
}
</style>
