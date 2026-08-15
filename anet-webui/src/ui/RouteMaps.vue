<script setup lang="ts">
// Редактор политик split tunneling. Каждое правило может быть CIDR или
// application; backend затем компилирует их в клиентский TOML.
import { computed, onMounted, ref } from 'vue'
import { CreateRouteMap, DeleteRouteMap, GetRouteMaps, UpdateRouteMap } from '@/api/route-maps'
import type { RouteMap, RouteRule, SaveRouteMapRequest } from '@/models/route-map'

const maps = ref<RouteMap[]>([])
const loading = ref(false)
const saving = ref(false)
const showEditor = ref(false)
const editingId = ref<string | null>(null)
const ruleKind = ref<'cidr' | 'application'>('cidr')
const form = ref<SaveRouteMapRequest>({
  name: '', description: '', default_action: 'tunnel', is_active: true, rules: [],
})

const oppositeAction = computed<'tunnel' | 'direct'>(() => form.value.default_action === 'tunnel' ? 'direct' : 'tunnel')
const actionOptions = [
  { label: 'Tunnel by default', value: 'tunnel' },
  { label: 'Direct by default', value: 'direct' },
]
const kindOptions = [
  { label: 'CIDR networks', value: 'cidr' },
  { label: 'Applications (Windows)', value: 'application' },
]

const normalizeRules = () => form.value.rules.map((rule, position) => ({
  ...rule, position, action: oppositeAction.value,
}))

const load = async () => {
  loading.value = true
  try { maps.value = await GetRouteMaps() } finally { loading.value = false }
}

const openCreate = () => {
  editingId.value = null
  ruleKind.value = 'cidr'
  form.value = { name: '', description: '', default_action: 'tunnel', is_active: true, rules: [] }
  showEditor.value = true
}

const openEdit = (map: RouteMap) => {
  editingId.value = map.id
  ruleKind.value = map.rules[0]?.match_type || 'cidr'
  form.value = {
    name: map.name, description: map.description, default_action: map.default_action,
    is_active: map.is_active, rules: map.rules.map(rule => ({ ...rule })),
  }
  showEditor.value = true
}

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

const changeKind = (kind: 'cidr' | 'application') => {
  ruleKind.value = kind
}

const save = async () => {
  saving.value = true
  try {
    const payload = { ...form.value, rules: normalizeRules() }
    if (editingId.value) await UpdateRouteMap(editingId.value, payload)
    else await CreateRouteMap(payload)
    showEditor.value = false
    await load()
  } finally { saving.value = false }
}

const remove = async (id: string) => { await DeleteRouteMap(id); await load() }
onMounted(load)
</script>

<template>
  <main class="route-page">
    <n-space justify="space-between" align="center" class="page-title">
      <div><h2>Route Maps</h2><span>Политики split tunneling для клиентских конфигураций</span></div>
      <n-button type="primary" @click="openCreate">Создать карту</n-button>
    </n-space>
    <n-alert type="info" :bordered="false" class="scope-alert">
      CIDR-карты работают на desktop и mobile. Application rules используют Windows per-app filtering.
      Domain/Geo и межузловые hops появятся вместе с соответствующим data plane.
    </n-alert>

    <n-spin :show="loading">
      <n-grid :cols="1" :y-gap="14">
        <n-grid-item v-for="map in maps" :key="map.id">
          <n-card hoverable @click="openEdit(map)">
            <n-space justify="space-between" align="start">
              <div>
                <n-space align="center">
                  <strong>{{ map.name }}</strong>
                  <n-tag :type="map.is_active ? 'success' : 'default'" size="small">{{ map.is_active ? 'ACTIVE' : 'DISABLED' }}</n-tag>
                  <n-tag size="small">rev {{ map.revision }}</n-tag>
                </n-space>
                <p>{{ map.description || 'Без описания' }}</p>
              </div>
              <n-space align="center">
                <n-statistic label="Rules" :value="map.rules.length" />
                <n-tag :type="map.default_action === 'tunnel' ? 'success' : 'warning'">default: {{ map.default_action }}</n-tag>
                <n-popconfirm @positive-click="remove(map.id)">
                  <template #trigger><n-button text type="error" @click.stop>Удалить</n-button></template>
                  Удалить карту? Назначения пользователей также будут удалены.
                </n-popconfirm>
              </n-space>
            </n-space>
          </n-card>
        </n-grid-item>
      </n-grid>
      <n-empty v-if="maps.length === 0" description="Маршрутных карт ещё нет" />
    </n-spin>

    <n-modal v-model:show="showEditor" preset="card" style="width: min(900px, calc(100vw - 40px))" :title="editingId ? 'Редактировать карту' : 'Создать карту'">
      <n-form>
        <n-grid :cols="2" :x-gap="16">
          <n-form-item-gi label="Название"><n-input v-model:value="form.name" /></n-form-item-gi>
          <n-form-item-gi label="Default action"><n-select v-model:value="form.default_action" :options="actionOptions" /></n-form-item-gi>
        </n-grid>
        <n-form-item label="Описание"><n-input v-model:value="form.description" type="textarea" /></n-form-item>
        <n-form-item label="Активна"><n-switch v-model:value="form.is_active" /></n-form-item>
        <n-form-item label="Тип новых правил">
          <n-select :value="ruleKind" :options="kindOptions" @update:value="changeKind" />
        </n-form-item>
        <n-divider>Rules · CIDR и application можно смешивать; совпадения отправляются {{ oppositeAction }}</n-divider>

        <n-space vertical style="width: 100%">
          <n-input-group v-for="(rule, index) in form.rules" :key="rule.id || index">
            <n-input-group-label style="width: 46px">{{ index + 1 }}</n-input-group-label>
            <n-select v-model:value="rule.match_type" :options="kindOptions" style="width: 175px" />
            <n-input
                v-model:value="rule.match_value"
                :placeholder="rule.match_type === 'cidr' ? '10.0.0.0/8' : 'steam.exe'"
            />
            <n-button :disabled="index === 0" @click="moveRule(index, -1)">↑</n-button>
            <n-button :disabled="index === form.rules.length - 1" @click="moveRule(index, 1)">↓</n-button>
            <n-button type="error" ghost @click="form.rules.splice(index, 1)">×</n-button>
          </n-input-group>
          <n-button dashed block @click="addRule">Добавить правило</n-button>
        </n-space>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showEditor = false">Отмена</n-button>
          <n-button type="primary" :loading="saving" :disabled="!form.name.trim() || form.rules.some(rule => !rule.match_value.trim())" @click="save">Сохранить</n-button>
        </n-space>
      </template>
    </n-modal>
  </main>
</template>

<style scoped>
.route-page { max-width: 1200px; margin: 0 auto; padding: 24px; }
.page-title { margin-bottom: 18px; }
.page-title h2 { margin: 0 0 4px; font-size: 22px; }
.page-title span, p { color: #94a3b8; font-size: 13px; }
.scope-alert { margin-bottom: 20px; }
p { margin: 8px 0 0; }
</style>
