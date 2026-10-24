<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { CreateRouteMap, UpdateRouteMap } from '@/api/route-maps'
import type { RouteMap, RouteRuleAction, RouteRuleMatchType, SaveRouteMapRequest } from '@/models/route-map'
import type { RuleProvider } from '@/models/rule-provider'
import { useAppMessage } from '@/composables/useAppMessage'

const show = defineModel<boolean>()

const props = defineProps<{
  routeMap: RouteMap | null
  providers?: RuleProvider[]
}>()

const emit = defineEmits<{
  (e: 'saved'): void
  (e: 'close'): void
}>()

const loading = ref(false)
const ruleKind = ref<RouteRuleMatchType>('cidr')
const message = useAppMessage()

const form = ref<SaveRouteMapRequest>({
  name: '',
  description: '',
  default_action: 'tunnel',
  is_active: true,
  rules: [],
})

const oppositeAction = computed<'tunnel' | 'direct'>(() =>
  form.value.default_action === 'tunnel' ? 'direct' : 'tunnel',
)

const actionOptions = [
  { title: 'Tunnel by default (Все в туннель)', value: 'tunnel' },
  { title: 'Direct by default (Все напрямую)', value: 'direct' },
]

const kindOptions: { title: string; value: RouteRuleMatchType }[] = [
  { title: 'CIDR сети (IP/Подсеть)', value: 'cidr' },
  { title: 'Домен / Поддомены (*.domain)', value: 'domain' },
  { title: 'Провайдер правил (.abc)', value: 'rule_provider' },
  { title: 'Приложения (Windows .exe)', value: 'application' },
]

const ruleActionOptions = computed<{ title: string; value: RouteRuleAction }[]>(() => [
  { title: 'DIRECT (В обход туннеля)', value: 'direct' },
  { title: 'TUNNEL (В туннель)', value: 'tunnel' },
  { title: 'BLOCK (AdBlock / 0.0.0.0)', value: 'block' },
])

const providerSelectItems = computed(() =>
  (props.providers || []).map(p => ({
    title: `${p.name} (${p.provider_type.toUpperCase()} · ${p.item_count} правил)`,
    value: p.id,
  })),
)

watch(
  () => props.routeMap,
  newVal => {
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
  { immediate: true },
)

const normalizeRules = () =>
  form.value.rules.map((rule, position) => ({
    ...rule,
    position,
    action: rule.match_type === 'application' ? oppositeAction.value : rule.action || oppositeAction.value,
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
    const errMessage = e?.response?.data?.error || e?.response?.data || e?.message || 'Не удалось сохранить карту'
    message.error(typeof errMessage === 'string' ? errMessage : JSON.stringify(errMessage))
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
  <v-dialog v-model="show" @update:model-value="close" max-width="960px">
    <v-card>
      <v-card-title class="text-h6 pb-4">
        {{ routeMap ? 'Редактировать карту маршрутизации' : 'Создать карту маршрутизации' }}
      </v-card-title>

      <v-card-text>
        <v-form>
          <v-row>
            <v-col cols="12" sm="6">
              <v-text-field v-model="form.name" label="Название" variant="filled" hide-details class="mb-3" />
            </v-col>
            <v-col cols="12" sm="6">
              <v-select
                v-model="form.default_action"
                :items="actionOptions"
                item-title="title"
                item-value="value"
                label="Default action"
                variant="filled"
                hide-details
                class="mb-3"
              />
            </v-col>
          </v-row>

          <v-textarea v-model="form.description" label="Описание" variant="filled" rows="2" class="mb-3" />

          <v-switch v-model="form.is_active" label="Активна (ВКЛ)" color="success" class="mb-1" />

          <v-select
            v-model="ruleKind"
            :items="kindOptions"
            item-title="title"
            item-value="value"
            label="Тип новых правил по умолчанию"
            variant="filled"
            hide-details
            class="mb-4"
          />

          <div class="d-flex align-center mt-4 mb-4">
            <v-divider class="flex-grow-1" />
            <span class="mx-4 text-caption text-medium-emphasis text-center">
              Правила профиля · Поддерживаются CIDR, Домены, Провайдеры (.abc) и Приложения
            </span>
            <v-divider class="flex-grow-1" />
          </div>

          <div class="d-flex flex-column ga-2 mb-4">
            <v-sheet
              v-for="(rule, index) in form.rules"
              :key="rule.id || index"
              color="surface-variant"
              rounded="lg"
              border
              class="d-flex align-center ga-3 pa-2 flex-wrap"
            >
              <span class="text-caption text-medium-emphasis text-center" style="min-width: 24px">
                {{ index + 1 }}
              </span>
              <v-select
                v-model="rule.match_type"
                :items="kindOptions"
                item-title="title"
                item-value="value"
                variant="filled"
                density="compact"
                hide-details
                style="max-width: 220px; min-width: 180px"
                @update:model-value="rule.match_value = ''"
              />

              <v-select
                v-if="rule.match_type === 'rule_provider'"
                v-model="rule.match_value"
                :items="providerSelectItems"
                item-title="title"
                item-value="value"
                label="Выберите провайдер правил"
                variant="filled"
                density="compact"
                hide-details
                class="flex-grow-1"
              />
              <v-text-field
                v-else
                v-model="rule.match_value"
                :placeholder="
                  rule.match_type === 'cidr'
                    ? '10.0.0.0/8'
                    : rule.match_type === 'domain'
                      ? '*.bank.ru или example.com'
                      : 'steam.exe'
                "
                variant="filled"
                density="compact"
                hide-details
                class="flex-grow-1"
              />

              <v-select
                v-model="rule.action"
                :items="ruleActionOptions"
                :disabled="rule.match_type === 'application'"
                item-title="title"
                item-value="value"
                variant="filled"
                density="compact"
                hide-details
                style="max-width: 195px; min-width: 165px"
              />

              <div class="d-flex ga-1">
                <v-btn variant="text" size="small" :disabled="index === 0" @click="moveRule(index, -1)">
                  <v-icon icon="mdi-arrow-up" />
                </v-btn>
                <v-btn
                  variant="text"
                  size="small"
                  :disabled="index === form.rules.length - 1"
                  @click="moveRule(index, 1)"
                >
                  <v-icon icon="mdi-arrow-down" />
                </v-btn>
                <v-btn color="error" variant="text" size="small" @click="form.rules.splice(index, 1)">
                  <v-icon icon="mdi-close" />
                </v-btn>
              </div>
            </v-sheet>

            <v-btn variant="tonal" class="mt-2" block @click="addRule"> Добавить правило </v-btn>
          </div>
        </v-form>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
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
