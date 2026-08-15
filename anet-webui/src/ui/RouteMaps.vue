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
    <div justify="space-between" align="center" class="page-title">
      <div><h2>Route Maps</h2><span>Политики split tunneling для клиентских конфигураций</span></div>
      <v-btn color="primary" @click="openCreate">Создать карту</v-btn>
    </div>
    <v-alert type="info" :bordered="false" class="scope-alert">
      CIDR-карты работают на desktop и mobile. Application rules используют Windows per-app filtering.
      Domain/Geo и межузловые hops появятся вместе с соответствующим data plane.
    </v-alert>

    <div class="position-relative">
      <v-row :cols="1" :y-gap="14">
        <v-col v-for="map in maps" :key="map.id">
          <v-card hoverable @click="openEdit(map)">
            <div justify="space-between" align="start">
              <div>
                <div align="center">
                  <strong>{{ map.name }}</strong>
                  <v-chip  :color="map.is_active ? 'success' : 'default'" size="small">{{ map.is_active ? 'ACTIVE' : 'DISABLED' }}</v-chip>
                  <v-chip size="small">rev {{ map.revision }}</v-chip>
                </div>
                <p>{{ map.description || 'Без описания' }}</p>
              </div>
              <div align="center">
                <div label="Rules" :modelValue="map.rules.length" />
                <v-chip  :color="map.default_action === 'tunnel' ? 'success' : 'warning'">default: {{ map.default_action }}</v-chip>
                <div>
                  <v-btn text color="error" @click.stop>Удалить</v-btn>
                  Удалить карту? Назначения пользователей также будут удалены.
                </div>
              </div>
            </div>
          </v-card>
        </v-col>
      </v-row>
      <v-empty-state v-if="maps.length === 0" description="Маршрутных карт ещё нет" />
    </div>

    <v-dialog v-model="showEditor" style="width: min(900px, calc(100vw - 40px))" :title="editingId ? 'Редактировать карту' : 'Создать карту'">
      <v-form>
        <v-row :cols="2" :x-gap="16">
          <div label="Название"><v-text-field v-model="form.name" /></div>
          <div label="Default action"><v-select v-model="form.default_action" :items="actionOptions" /></div>
        </v-row>
        <div label="Описание"><v-text-field v-model="form.description" type="textarea" /></div>
        <div label="Активна"><v-switch v-model="form.is_active" /></div>
        <div label="Тип новых правил">
          <v-select :modelValue="ruleKind" :items="kindOptions" @update:modelValue="changeKind" />
        </div>
        <v-divider>Rules · CIDR и application можно смешивать; совпадения отправляются {{ oppositeAction }}</v-divider>

        <div vertical style="width: 100%">
          <div v-for="(rule, index) in form.rules" :key="rule.id || index">
            <span style="width: 46px">{{ index + 1 }}</span>
            <v-select v-model="rule.match_type" :items="kindOptions" style="width: 175px" />
            <v-text-field
                v-model="rule.match_value"
                :placeholder="rule.match_type === 'cidr' ? '10.0.0.0/8' : 'steam.exe'"
            />
            <v-btn :disabled="index === 0" @click="moveRule(index, -1)">↑</v-btn>
            <v-btn :disabled="index === form.rules.length - 1" @click="moveRule(index, 1)">↓</v-btn>
            <v-btn color="error" ghost @click="form.rules.splice(index, 1)">×</v-btn>
          </div>
          <v-btn dashed block @click="addRule">Добавить правило</v-btn>
        </div>
      </v-form>
      <div class="d-flex justify-end ga-4">
        <div justify="end">
          <v-btn @click="showEditor = false">Отмена</v-btn>
          <v-btn color="primary" :loading="saving" :disabled="!form.name.trim() || form.rules.some(rule => !rule.match_value.trim())" @click="save">Сохранить</v-btn>
        </div>
      </div>
    </v-dialog>
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
