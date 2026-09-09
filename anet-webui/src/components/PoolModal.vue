<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { CreatePool, UpdatePool } from '@/api/pools'
import type { NodePool, ProtocolType, SaveNodePoolRequest } from '@/models/pool'
import type { Server } from '@/models/server'
import { useAppMessage } from '@/composables/useAppMessage'

const show = defineModel<boolean>()

const props = defineProps<{
  pool: NodePool | null
  servers: Server[]
}>()

const emit = defineEmits<{
  (e: 'saved'): void
  (e: 'close'): void
}>()

const message = useAppMessage()

const form = ref<SaveNodePoolRequest>({
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
  { title: 'AHTTP / HTTP(S)', value: 'ahttp' },
  { title: 'WebSocket (WS/WSS)', value: 'ws' },
  { title: 'SSH', value: 'ssh' },
  { title: 'VNC', value: 'vnc' },
]

const serverById = computed(() => new Map(props.servers.map(server => [server.id, server])))

watch(
    () => props.pool,
    (newVal) => {
      if (newVal) {
        form.value = {
          name: newVal.name,
          strategy: newVal.strategy,
          is_active: newVal.is_active,
          members: newVal.members.map(member => ({
            server_id: member.server_id,
            protocol: member.protocol || 'quic',
            port_or_url: member.port_or_url || '',
            weight: member.weight || 1,
          })),
        }
      } else {
        form.value = { name: '', strategy: 'weighted', is_active: true, members: [] }
      }
    },
    { immediate: true }
)

const addNode = (serverId: string) => {
  form.value.members.push({
    server_id: serverId,
    protocol: 'quic',
    port_or_url: '',
    weight: 1,
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
                  />
                </v-col>
                <v-col cols="12" sm="5">
                  <v-text-field
                      v-model="member.port_or_url"
                      label="Порт или URL"
                      :placeholder="member.protocol === 'ahttp' || member.protocol === 'ws' ? 'URL (напр. cdn / tunnel)' : 'Порт (напр. 443)'"
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
</template>
