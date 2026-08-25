<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { CreateRouteMap, UpdateRouteMap } from '@/api/route-maps'
import type { RouteMap, SaveRouteMapRequest } from '@/models/route-map'
import { useAppMessage } from '@/composables/useAppMessage'

const show = defineModel<boolean>()

const props = defineProps<{
  routeMap: RouteMap | null
}>()

const emit = defineEmits<{
  (e: 'saved'): void
  (e: 'close'): void
}>()

const loading = ref(false)
const ruleKind = ref<'cidr' | 'application'>('cidr')
const message = useAppMessage()

const form = ref<SaveRouteMapRequest>({
  name: '',
  description: '',
  default_action: 'tunnel',
  is_active: true,
  rules: [],
})

const oppositeAction = computed<'tunnel' | 'direct'>(() =>
    form.value.default_action === 'tunnel' ? 'direct' : 'tunnel'
)

const actionOptions = [
  { title: 'Tunnel by default', value: 'tunnel' },
  { title: 'Direct by default', value: 'direct' },
]

const kindOptions = [
  { title: 'CIDR networks', value: 'cidr' },
  { title: 'Applications (Windows)', value: 'application' },
]

watch(
    () => props.routeMap,
    (newVal) => {
      if (newVal) {
        ruleKind.value = newVal.rules[0]?.match_type || 'cidr'
        form.value = {
          name: newVal.name,
          description: newVal.description,
          default_action: newVal.default_action,
          is_active: newVal.is_active,
          rules: newVal.rules.map(rule => ({ ...rule })),
        }
      } else {
        ruleKind.value = 'cidr'
        form.value = { name: '', description: '', default_action: 'tunnel', is_active: true, rules: [] }
      }
    },
    { immediate: true }
)

const normalizeRules = () => form.value.rules.map((rule, position) => ({
  ...rule,
  position,
  action: oppositeAction.value
}))

const addRule = () => {
  form.value.rules.push({
    position: form.value.rules.length,
    match_type: ruleKind.value,
    match_value: '',
    action: oppositeAction.value,
  })
}

const moveRule = (index: number, direction: -1 | 1) => {
  const target = index + direction
  if (target < 0 || target >= form.value.rules.length) return
  const [rule] = form.value.rules.splice(index, 1)
  if (rule) form.value.rules.splice(target, 0, rule)
}

const save = async () => {
  loading.value = true
  try {
    const payload = { ...form.value, rules: normalizeRules() }
    if (props.routeMap?.id) {
      await UpdateRouteMap(props.routeMap.id, payload)
    } else {
      await CreateRouteMap(payload)
    }
    message.success('Маршрутная карта успешно сохранена')
    emit('saved')
    show.value = false
  } catch (e: any) {
    // Выводим ошибку от бэкенда (например, про неверный CIDR) в интерфейс
    const errMessage = e?.response?.data?.error || e?.message || 'Не удалось сохранить карту'
    message.error(errMessage)
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
  <v-dialog v-model="show" @update:model-value="close" max-width="900px">
    <v-card>
      <v-card-title class="text-h6 pb-4">
        {{ routeMap ? 'Редактировать карту' : 'Создать карту' }}
      </v-card-title>

      <v-card-text>
        <v-form>
          <v-row>
            <v-col cols="12" sm="6">
              <v-text-field v-model="form.name" label="Название" variant="outlined" hide-details class="mb-3" />
            </v-col>
            <v-col cols="12" sm="6">
              <v-select
                  v-model="form.default_action"
                  :items="actionOptions"
                  item-title="title"
                  item-value="value"
                  label="Default action"
                  variant="outlined"
                  hide-details
                  class="mb-3"
              />
            </v-col>
          </v-row>

          <v-textarea v-model="form.description" label="Описание" variant="outlined" rows="2" class="mb-3" />

          <v-switch v-model="form.is_active" label="Активна (ВКЛ)" color="success" class="mb-1" />

          <v-select
              v-model="ruleKind"
              :items="kindOptions"
              item-title="title"
              item-value="value"
              label="Тип новых правил по умолчанию"
              variant="outlined"
              hide-details
              class="mb-4"
          />

          <div class="d-flex align-center mt-4 mb-4">
            <v-divider class="flex-grow-1"></v-divider>
            <span class="mx-4 text-caption text-medium-emphasis text-center">
              Rules · CIDR и application можно смешивать; совпадения отправляются <strong>{{ oppositeAction }}</strong>
            </span>
            <v-divider class="flex-grow-1"></v-divider>
          </div>

          <div class="d-flex flex-column gap-2 mb-4">
            <div
                v-for="(rule, index) in form.rules"
                :key="rule.id || index"
                class="d-flex align-center gap-3 pa-2 rounded bg-grey-darken-4 border"
            >
              <div class="text-caption text-medium-emphasis text-center" style="min-width: 24px">
                {{ index + 1 }}
              </div>
              <v-select
                  v-model="rule.match_type"
                  :items="kindOptions"
                  item-title="title"
                  item-value="value"
                  variant="outlined"
                  density="compact"
                  hide-details
                  style="max-width: 200px"
              />
              <v-text-field
                  v-model="rule.match_value"
                  :placeholder="rule.match_type === 'cidr' ? '10.0.0.0/8' : 'steam.exe'"
                  variant="outlined"
                  density="compact"
                  hide-details
                  class="flex-grow-1"
              />
              <div class="d-flex gap-1">
                <v-btn variant="text" size="small" :disabled="index === 0" @click="moveRule(index, -1)">↑</v-btn>
                <v-btn variant="text" size="small" :disabled="index === form.rules.length - 1" @click="moveRule(index, 1)">↓</v-btn>
                <v-btn color="error" variant="text" size="small" @click="form.rules.splice(index, 1)">×</v-btn>
              </div>
            </div>

            <v-btn variant="tonal" class="mt-2" block @click="addRule">
              Добавить правило
            </v-btn>
          </div>
        </v-form>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer></v-spacer>
        <v-btn variant="text" @click="close">Отмена</v-btn>
        <v-btn
            color="primary"
            variant="flat"
            :loading="loading"
            :disabled="!form.name.trim() || form.rules.some(rule => !rule.match_value?.trim())"
            @click="save"
        >
          Сохранить
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.gap-1 { gap: 4px; }
.gap-2 { gap: 8px; }
.gap-3 { gap: 12px; }
.border { border: 1px solid rgba(255, 255, 255, 0.12); }
</style>
