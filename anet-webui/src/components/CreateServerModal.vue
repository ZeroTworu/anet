<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { CreateServer } from '@/api/servers'
import type { CreateServerRequest } from '@/models/server'
import {
  useDohResolvers,
  parseDohDsn,
  buildDohDsn,
} from '@/utils/doh'
import DohResolversModal from '@/components/DohResolversModal.vue'

const show = defineModel<boolean>()
const showResolversModal = ref(false)
const { presetResolvers, defaultResolvers, ensureLoaded } = useDohResolvers()

onMounted(async () => {
  await ensureLoaded()
  dohResolvers.value = [...defaultResolvers.value]
})

const emit = defineEmits<{
  (e: 'created'): void
  (e: 'close'): void
}>()

const loading = ref(false)

const defaultForm = (): CreateServerRequest => ({
  name: '',
  address: '127.0.0.1',
  public_key: '',
  ssh_user: 'hanyuu',
  is_active: true,
  quic_port: 4519,
  ssh_port: 822,
  vnc_port: 56678,
  websocket_url: 'ws://127.0.0.1:8080/socket',
  ahttp_url: 'https://your-cdn.some-host.net/api/v2/telemetry',
  wrtc_url: 'wrtc://meet.jit.si/your-telemetry-room',
  wrtc_mode: 'media_video',
  doh_url: '',
})

const wrtcModeOptions = [
  { title: 'Media Video (Fake Video Track over DTLS-SRTP / JVB) - 4K/Макс. скорость', value: 'media_video' },
  { title: 'P2P Direct (Прямой WebRTC DataChannel)', value: 'p2p_direct' },
  { title: 'JVB DataChannel (Colibri SCTP DataChannel)', value: 'jvb_datachannel' },
  { title: 'WebSocket (Colibri-WS Fallback)', value: 'ws' },
  { title: 'Auto (Автоматический выбор)', value: 'auto' },
]

const form = ref<CreateServerRequest>(defaultForm())

const dohDomain = ref('')
const dohResolvers = ref<string[]>([...defaultResolvers.value])
const dohArq = ref(true)
const dohDupHs = ref(true)
const dohHoldMs = ref(1200)

watch(
  () => show.value,
  async (isOpen) => {
    if (isOpen) {
      await ensureLoaded()
      if (!dohDomain.value.trim()) {
        dohResolvers.value = [...defaultResolvers.value]
      }
    }
  },
)

const syncDohUrl = () => {
  if (dohDomain.value.includes('?') || dohDomain.value.includes('://')) {
    const parsed = parseDohDsn(dohDomain.value)
    dohDomain.value = parsed.domain
    if (parsed.resolvers.length > 0) {
      dohResolvers.value = parsed.resolvers
    }
    dohArq.value = parsed.arq
    dohDupHs.value = parsed.dup_hs
    dohHoldMs.value = parsed.hold_ms
  }
  form.value.doh_url = buildDohDsn({
    domain: dohDomain.value,
    resolvers: dohResolvers.value,
    arq: dohArq.value,
    dup_hs: dohDupHs.value,
    hold_ms: dohHoldMs.value,
  })
}

const handleCreate = async () => {
  syncDohUrl()
  loading.value = true
  try {
    await CreateServer(form.value)
    form.value = defaultForm()
    dohDomain.value = ''
    dohResolvers.value = [...defaultResolvers.value]
    dohArq.value = true
    dohDupHs.value = true
    dohHoldMs.value = 1200
    emit('created')
    show.value = false
  } catch (error: any) {
    console.error('Ошибка при создании сервера:', error)
    if (error.response?.data) {
      alert(`Ошибка: ${error.response.data}`)
    } else {
      alert('Произошла ошибка при создании сервера')
    }
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
  <v-dialog v-model="show" @update:model-value="close" max-width="650px">
    <v-card>
      <v-card-title class="text-h6 pb-4">
        Добавить физический сервер
      </v-card-title>

      <v-card-text>
        <v-form>
          <v-text-field
              v-model="form.name"
              label="Название локации"
              placeholder="e.g. Germany VPS 1"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="form.address"
              label="IP Адрес или Домен"
              placeholder="e.g. 203.0.113.10 или vpn.example.com"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="form.public_key"
              label="Публичный ключ сервера (server_pub_key)"
              placeholder="Из утилиты anet-keygen"
              variant="filled"
              class="mb-3"
          />

          <v-row class="mb-1">
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.quic_port"
                  type="number"
                  label="QUIC Port (UDP)"
                  variant="filled"
                  hide-details
              />
            </v-col>
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.ssh_port"
                  type="number"
                  label="SSH Port (TCP)"
                  variant="filled"
                  hide-details
              />
            </v-col>
            <v-col cols="12" sm="4">
              <v-text-field
                  v-model.number="form.vnc_port"
                  type="number"
                  label="VNC Port (TCP)"
                  variant="filled"
                  hide-details
              />
            </v-col>
          </v-row>

          <v-text-field
              v-model="form.websocket_url"
              label="WebSocket URL"
              placeholder="ws://127.0.0.1:8080/s"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="form.ahttp_url"
              label="AHTTP URL (CDN)"
              placeholder="https://your-cdn.some-host.net/api/v2/telemetry"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="form.wrtc_url"
              label="WRTC URL (Jitsi / WebRTC Room)"
              placeholder="wrtc://meet.jit.si/your-telemetry-room"
              variant="filled"
              class="mb-3"
          />

          <v-select
              v-if="form.wrtc_url"
              v-model="form.wrtc_mode"
              :items="wrtcModeOptions"
              item-title="title"
              item-value="value"
              label="Режим WRTC (wrtc_mode)"
              variant="filled"
              class="mb-3"
          />

          <v-text-field
              v-model="dohDomain"
              label="DoH Доменная зона (DNS-over-HTTPS)"
              placeholder="t1.anet-project.org"
              variant="filled"
              class="mb-3"
              @update:model-value="syncDohUrl"
          />

          <v-sheet v-if="dohDomain.trim()" color="surface-variant" rounded="lg" border class="pa-3 mb-3">
            <div class="d-flex justify-space-between align-center mb-1">
              <span class="text-caption text-medium-emphasis">Публичные DoH-резолверы (?resolver=...)</span>
              <v-btn
                  size="x-small"
                  variant="tonal"
                  color="primary"
                  prepend-icon="mdi-database-cog-outline"
                  @click="showResolversModal = true"
              >
                Настроить список в БД
              </v-btn>
            </div>
            <v-combobox
                v-model="dohResolvers"
                :items="presetResolvers"
                placeholder="Выберите из БД или введите URL и нажмите Enter"
                multiple
                chips
                closable-chips
                density="compact"
                variant="outlined"
                hide-details
                class="mb-2"
                @update:model-value="syncDohUrl"
            />
            <v-row dense align="center">
              <v-col cols="12" sm="4">
                <v-checkbox
                    v-model="dohArq"
                    label="ARQ (Selective Repeat)"
                    density="compact"
                    color="primary"
                    hide-details
                    @update:model-value="syncDohUrl"
                />
              </v-col>
              <v-col cols="12" sm="4">
                <v-checkbox
                    v-model="dohDupHs"
                    label="Дублировать Handshake"
                    density="compact"
                    color="primary"
                    hide-details
                    @update:model-value="syncDohUrl"
                />
              </v-col>
              <v-col cols="12" sm="4">
                <v-text-field
                    v-model.number="dohHoldMs"
                    type="number"
                    label="Long-poll (hold_ms)"
                    min="100"
                    max="5000"
                    density="compact"
                    variant="outlined"
                    hide-details
                    @update:model-value="syncDohUrl"
                />
              </v-col>
            </v-row>
            <div v-if="form.doh_url" class="text-caption text-medium-emphasis text-truncate mt-2">
              DSN: <code>{{ form.doh_url }}</code>
            </div>
          </v-sheet>

          <v-text-field
              v-model="form.ssh_user"
              label="Пользователь SSH (ssh_user)"
              placeholder="hanyuu"
              variant="filled"
              class="mb-3"
          />

          <v-switch
              v-model="form.is_active"
              label="Активен (ВКЛ)"
              color="success"
              class="mb-2"
          />
        </v-form>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
        <v-btn variant="text" @click="close">Cancel</v-btn>
        <v-btn color="primary" variant="flat" :loading="loading" @click="handleCreate">
          Add Node
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <DohResolversModal v-model="showResolversModal" />
</template>
