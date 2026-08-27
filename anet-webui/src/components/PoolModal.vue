<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { CreatePool, UpdatePool } from '@/api/pools'
import type { NodePool, SaveNodePoolRequest } from '@/models/pool'
import type { Server } from '@/models/server'

const show = defineModel<boolean>()

const props = defineProps<{
  pool: NodePool | null
  servers: Server[]
}>()

const emit = defineEmits<{
  (e: 'saved'): void
  (e: 'close'): void
}>()

const form = ref<SaveNodePoolRequest>({
  name: '',
  strategy: 'weighted',
  is_active: true,
  members: [],
})

const loading = ref(false)

// ИСПРАВЛЕНО: Заменили label на title для корректной работы <v-select>
const strategyOptions = [
  { title: 'Weighted rendezvous', value: 'weighted' },
  { title: 'Least connections', value: 'least_connections' },
]

const selectedIds = computed(() => new Set(form.value.members.map(member => member.server_id)))
const availableServers = computed(() => props.servers.filter(server => !selectedIds.value.has(server.id)))
const serverById = computed(() => new Map(props.servers.map(server => [server.id, server])))

watch(
    () => props.pool,
    (newVal) => {
      if (newVal) {
        form.value = {
          name: newVal.name,
          strategy: newVal.strategy,
          is_active: newVal.is_active,
          members: newVal.members.map(member => ({ ...member })),
        }
      } else {
        form.value = { name: '', strategy: 'weighted', is_active: true, members: [] }
      }
    },
    { immediate: true }
)

const addNode = (serverId: string) => {
  form.value.members.push({ server_id: serverId, weight: 1 })
}

const removeNode = (index: number) => {
  form.value.members.splice(index, 1)
}

const save = async () => {
  loading.value = true
  try {
    if (props.pool?.id) {
      await UpdatePool(props.pool.id, form.value)
    } else {
      await CreatePool(form.value)
    }
    emit('saved')
    show.value = false
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
  <v-dialog v-model="show" @update:model-value="close" max-width="720px">
    <v-card>
      <v-card-title class="text-h6 pb-4">
        {{ pool ? 'Редактировать pool' : 'Создать pool' }}
      </v-card-title>

      <v-card-text>
        <v-form>
          <v-text-field
              v-model="form.name"
              label="Название"
              variant="filled"
              class="mb-3"
          />

          <v-select
              v-model="form.strategy"
              :items="strategyOptions"
              item-title="title"
              item-value="value"
              label="Стратегия"
              variant="filled"
              class="mb-3"
          />

          <v-switch
              v-model="form.is_active"
              label="Активен (ВКЛ)"
              color="success"
              class="mb-2"
          />

          <div class="d-flex align-center mt-2 mb-4">
            <v-divider class="flex-grow-1" />
            <span class="mx-4 text-medium-emphasis">Узлы</span>
            <v-divider class="flex-grow-1" />
          </div>

          <div class="d-flex flex-column ga-3 mb-4">
            <v-sheet
                v-for="(member, index) in form.members"
                :key="member.server_id"
                color="surface-variant"
                rounded="lg"
                border
                class="d-flex align-center justify-space-between pa-3"
            >
              <span class="font-weight-medium">
                {{ serverById.get(member.server_id)?.name || member.server_id }}
              </span>
              <div class="d-flex align-center ga-3">
                <!-- Используем обычный v-text-field type="number", так как v-number-input в Vuetify 3 пока экспериментальный -->
                <v-text-field
                    v-model.number="member.weight"
                    type="number"
                    label="Вес"
                    min="1"
                    max="10000"
                    density="compact"
                    hide-details
                    style="width: 100px"
                />
                <v-btn color="error" variant="text" size="small" @click="removeNode(index)">Убрать</v-btn>
              </div>
            </v-sheet>
          </div>

          <v-select
              v-if="availableServers.length"
              :model-value="null"
              :items="availableServers.map(server => ({ title: `${server.name} (${server.dsn})`, value: server.id }))"
              item-title="title"
              item-value="value"
              label="Добавить узел"
              placeholder="Выберите сервер из списка"
              variant="filled"
              @update:model-value="val => val && addNode(String(val))"
          />
          <v-alert v-else type="info" variant="tonal" density="compact">
            Нет доступных серверов для добавления
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
