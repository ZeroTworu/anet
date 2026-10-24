<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { CreatePool, UpdatePool } from '@/api/pools'
import type { NodePool, ProtocolType, SaveNodePoolRequest } from '@/models/pool'
import type { Server } from '@/models/server'
import { useAppMessage } from '@/composables/useAppMessage'
import {
  useDohResolvers,
  parseDohDsn,
  buildDohDsn,
} from '@/utils/doh'
import DohResolversModal from '@/components/DohResolversModal.vue'

const show = defineModel<boolean>()
const showResolversModal = ref(false)
const { presetResolvers, defaultResolvers, ensureLoaded } = useDohResolvers()

onMounted(() => {
  ensureLoaded()
})

const props = defineProps<{
  pool: NodePool | null
  servers: Server[]
}>()

const emit = defineEmits<{
  (e: 'saved'): void
  (e: 'close'): void
}>()

const message = useAppMessage()

type PoolMemberFormItem = {
  server_id: string
  protocol: ProtocolType
  port_or_url: string
  wrtc_mode: string
  weight: number
  doh_domain: string
  doh_resolvers: string[]
  doh_arq: boolean
  doh_dup_hs: boolean
  doh_hold_ms: number
}

const form = ref<{
  name: string
  strategy: 'weighted' | 'least_connections'
  is_active: boolean
  members: PoolMemberFormItem[]
}>({
  name: '',
  strategy: 'weighted',
  is_active: true,
  members: [],
})

const loading = ref(false)

const strategyOptions = [
  { title: 'Weighted rendezvous', value: 'weighted' },
  { title: 'Least connections', value: 'least_connections' },
]

const protocolOptions: { title: string; value: ProtocolType }[] = [
  { title: 'QUIC', value: 'quic' },
  { title: 'WRTC / Jitsi WebRTC', value: 'wrtc' },
  { title: 'DoH (DNS-over-HTTPS)', value: 'doh' },
  { title: 'AHTTP / HTTP(S)', value: 'ahttp' },
  { title: 'WebSocket (WS/WSS)', value: 'ws' },
  { title: 'SSH', value: 'ssh' },
  { title: 'VNC', value: 'vnc' },
]

const wrtcModeOptions = [
  { title: 'Media Video (Fake Video Track over DTLS-SRTP / JVB) - 4K/Макс. скорость', value: 'media_video' },
  { title: 'P2P Direct (Прямой WebRTC DataChannel)', value: 'p2p_direct' },
  { title: 'JVB DataChannel (Colibri SCTP DataChannel)', value: 'jvb_datachannel' },
  { title: 'WebSocket (Colibri-WS Fallback)', value: 'ws' },
  { title: 'Auto (Автоматический выбор)', value: 'auto' },
]

const getEndpointPlaceholder = (protocol: ProtocolType) => {
  if (protocol === 'doh') {
    return 't1.anet-project.org'
  }
  if (protocol === 'ahttp' || protocol === 'ws' || protocol === 'wrtc') {
    return 'URL (напр. cdn / room / tunnel)'
  }
  return 'Порт (напр. 443)'
}

const serverById = computed(() => new Map(props.servers.map(server => [server.id, server])))

const syncMemberDohDsn = (member: PoolMemberFormItem) => {
  if (member.protocol !== 'doh') return
  // Если пользователь вставил полный URL с ?resolver=..., распарсим его
  if (member.doh_domain.includes('?') || member.doh_domain.includes('://')) {
    const parsed = parseDohDsn(member.doh_domain)
    member.doh_domain = parsed.domain
    if (member.doh_domain.includes('?')) {
      member.doh_resolvers = parsed.resolvers
      member.doh_arq = parsed.arq
      member.doh_dup_hs = parsed.dup_hs
      member.doh_hold_ms = parsed.hold_ms
    }
  }
  member.port_or_url = buildDohDsn({
    domain: member.doh_domain,
    resolvers: member.doh_resolvers,
    arq: member.doh_arq,
    dup_hs: member.doh_dup_hs,
    hold_ms: member.doh_hold_ms,
  })
}

const onMemberProtocolChange = (member: PoolMemberFormItem) => {
  if (member.protocol === 'doh') {
    const serverDohUrl = serverById.value.get(member.server_id)?.doh_url || ''
    const rawSource = member.port_or_url || serverDohUrl
    const parsed = parseDohDsn(rawSource)
    member.doh_domain = parsed.domain
    member.doh_resolvers = parsed.resolvers
    member.doh_arq = parsed.arq
    member.doh_dup_hs = parsed.dup_hs
    member.doh_hold_ms = parsed.hold_ms
    syncMemberDohDsn(member)
  }
}

watch(
    () => props.pool,
    (newVal) => {
      if (newVal) {
        form.value = {
          name: newVal.name,
          strategy: newVal.strategy,
          is_active: newVal.is_active,
          members: newVal.members.map(member => {
            const proto = member.protocol || 'quic'
            const serverDohUrl = serverById.value.get(member.server_id)?.doh_url || ''
            const parsedDoh = parseDohDsn(proto === 'doh' ? (member.port_or_url || serverDohUrl) : '')
            const item: PoolMemberFormItem = {
              server_id: member.server_id,
              protocol: proto,
              port_or_url: member.port_or_url || '',
              wrtc_mode: member.wrtc_mode || 'media_video',
              weight: member.weight || 1,
              doh_domain: parsedDoh.domain,
              doh_resolvers: parsedDoh.resolvers,
              doh_arq: parsedDoh.arq,
              doh_dup_hs: parsedDoh.dup_hs,
              doh_hold_ms: parsedDoh.hold_ms,
            }
            if (proto === 'doh') {
              syncMemberDohDsn(item)
            }
            return item
          }),
        }
      } else {
        form.value = { name: '', strategy: 'weighted', is_active: true, members: [] }
      }
    },
    { immediate: true }
)

const addNode = (serverId: string) => {
  const srv = serverById.value.get(serverId)
  const parsedDoh = parseDohDsn(srv?.doh_url)
  form.value.members.push({
    server_id: serverId,
    protocol: 'quic',
    port_or_url: '',
    wrtc_mode: 'media_video',
    weight: 1,
    doh_domain: parsedDoh.domain,
    doh_resolvers: [...defaultResolvers.value],
    doh_arq: true,
    doh_dup_hs: true,
    doh_hold_ms: 1200,
  })
}

const removeNode = (index: number) => {
  form.value.members.splice(index, 1)
}

const save = async () => {
  // Проверяем на дубликаты комбинаций сервер + протокол
  const seen = new Set<string>()
  for (const m of form.value.members) {
    const key = `${m.server_id}:${m.protocol}`
    if (seen.has(key)) {
      message.error(`Сервер "${serverById.value.get(m.server_id)?.name || m.server_id}" уже добавлен с протоколом ${m.protocol.toUpperCase()}`)
      return
    }
    seen.add(key)
    if (m.protocol === 'doh') {
      syncMemberDohDsn(m)
    }
  }

  loading.value = true
  try {
    const payload: SaveNodePoolRequest = {
      name: form.value.name.trim(),
      strategy: form.value.strategy,
      is_active: form.value.is_active,
      members: form.value.members.map(m => ({
        server_id: m.server_id,
        protocol: m.protocol,
        port_or_url: m.port_or_url?.trim() || null,
        wrtc_mode: m.protocol === 'wrtc' ? (m.wrtc_mode || 'media_video') : null,
        weight: m.weight || 1,
      })),
    }

    if (props.pool?.id) {
      await UpdatePool(props.pool.id, payload)
    } else {
      await CreatePool(payload)
    }
    emit('saved')
    show.value = false
  } catch (e: any) {
    message.error(e?.response?.data || 'Не удалось сохранить группу серверов')
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
  <v-dialog v-model="show" @update:model-value="close" max-width="780px">
    <v-card>
      <v-card-title class="text-h6 pb-4">
        {{ pool ? 'Редактировать группу серверов' : 'Создать группу серверов' }}
      </v-card-title>

      <v-card-text>
        <v-form>
          <v-text-field
              v-model="form.name"
              label="Название группы"
              placeholder="e.g. Германия - Быстрая, Обход Белых Списков"
              variant="filled"
              class="mb-3"
          />

          <v-select
              v-model="form.strategy"
              :items="strategyOptions"
              item-title="title"
              item-value="value"
              label="Стратегия распределения"
              variant="filled"
              class="mb-3"
          />

          <v-switch
              v-model="form.is_active"
              label="Активна (ВКЛ)"
              color="success"
              class="mb-2"
          />

          <div class="d-flex align-center mt-2 mb-4">
            <v-divider class="flex-grow-1" />
            <span class="mx-4 text-medium-emphasis">Сервера и протоколы ({{ form.members.length }})</span>
            <v-divider class="flex-grow-1" />
          </div>

          <div class="d-flex flex-column ga-3 mb-4">
            <v-sheet
                v-for="(member, index) in form.members"
                :key="`${member.server_id}-${index}`"
                color="surface-variant"
                rounded="lg"
                border
                class="pa-3"
            >
              <div class="d-flex align-center justify-space-between mb-2">
                <div class="d-flex align-center ga-2">
                  <v-icon icon="mdi-server" size="small" />
                  <span class="font-weight-bold">
                    {{ serverById.get(member.server_id)?.name || member.server_id }}
                  </span>
                  <span class="text-caption text-medium-emphasis">
                    ({{ serverById.get(member.server_id)?.address }})
                  </span>
                </div>
                <v-btn color="error" variant="text" size="small" icon="mdi-delete" @click="removeNode(index)" />
              </div>

              <v-row dense align="center">
                <v-col cols="12" sm="4">
                  <v-select
                      v-model="member.protocol"
                      :items="protocolOptions"
                      item-title="title"
                      item-value="value"
                      label="Протокол"
                      density="compact"
                      variant="outlined"
                      hide-details
                      @update:model-value="onMemberProtocolChange(member)"
                  />
                </v-col>
                <v-col cols="12" sm="5">
                  <v-text-field
                      v-if="member.protocol === 'doh'"
                      v-model="member.doh_domain"
                      label="Доменная зона DoH (NS)"
                      placeholder="t1.anet-project.org"
                      density="compact"
                      variant="outlined"
                      hide-details
                      @update:model-value="syncMemberDohDsn(member)"
                  />
                  <v-text-field
                      v-else
                      v-model="member.port_or_url"
                      label="Порт или URL"
                      :placeholder="getEndpointPlaceholder(member.protocol)"
                      density="compact"
                      variant="outlined"
                      hide-details
                  />
                </v-col>
                <v-col cols="12" sm="3">
                  <v-text-field
                      v-model.number="member.weight"
                      type="number"
                      label="Вес (1-10000)"
                      min="1"
                      max="10000"
                      density="compact"
                      variant="outlined"
                      hide-details
                  />
                </v-col>
                <v-col v-if="member.protocol === 'wrtc'" cols="12" class="mt-2">
                  <v-select
                      v-model="member.wrtc_mode"
                      :items="wrtcModeOptions"
                      item-title="title"
                      item-value="value"
                      label="Режим WRTC (wrtc_mode)"
                      density="compact"
                      variant="outlined"
                      hide-details
                  />
                </v-col>

                <template v-if="member.protocol === 'doh'">
                  <v-col cols="12" class="mt-2">
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
                        v-model="member.doh_resolvers"
                        :items="presetResolvers"
                        placeholder="Выберите из БД или введите URL и нажмите Enter"
                        multiple
                        chips
                        closable-chips
                        density="compact"
                        variant="outlined"
                        hide-details
                        @update:model-value="syncMemberDohDsn(member)"
                    />
                  </v-col>
                  <v-col cols="12" sm="4" class="mt-2">
                    <v-checkbox
                        v-model="member.doh_arq"
                        label="ARQ (Selective Repeat)"
                        density="compact"
                        color="primary"
                        hide-details
                        @update:model-value="syncMemberDohDsn(member)"
                    />
                  </v-col>
                  <v-col cols="12" sm="4" class="mt-2">
                    <v-checkbox
                        v-model="member.doh_dup_hs"
                        label="Дублировать Handshake (dup_hs)"
                        density="compact"
                        color="primary"
                        hide-details
                        @update:model-value="syncMemberDohDsn(member)"
                    />
                  </v-col>
                  <v-col cols="12" sm="4" class="mt-2">
                    <v-text-field
                        v-model.number="member.doh_hold_ms"
                        type="number"
                        label="Long-poll (hold_ms)"
                        min="100"
                        max="5000"
                        density="compact"
                        variant="outlined"
                        hide-details
                        @update:model-value="syncMemberDohDsn(member)"
                    />
                  </v-col>
                  <v-col v-if="member.port_or_url" cols="12" class="mt-1">
                    <div class="text-caption text-medium-emphasis text-truncate">
                      DSN: <code>{{ member.port_or_url }}</code>
                    </div>
                  </v-col>
                </template>
              </v-row>
            </v-sheet>
          </div>

          <v-select
              v-if="props.servers.length"
              :model-value="null"
              :items="props.servers.map(server => ({ title: `${server.name} (${server.address})`, value: server.id }))"
              item-title="title"
              item-value="value"
              label="Добавить сервер в группу"
              placeholder="Выберите сервер из списка"
              variant="filled"
              @update:model-value="val => val && addNode(String(val))"
          />
          <v-alert v-else type="info" variant="tonal" density="compact">
            Нет доступных серверов
          </v-alert>
        </v-form>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
        <v-btn variant="text" @click="close">Отмена</v-btn>
        <v-btn color="primary" variant="flat" :loading="loading" :disabled="!form.name.trim()" @click="save">
          Сохранить
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <DohResolversModal v-model="showResolversModal" />
</template>
