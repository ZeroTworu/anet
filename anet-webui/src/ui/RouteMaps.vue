<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { DeleteRouteMap, GetRouteMaps } from '@/api/route-maps'
import {
  CreateRuleProvider,
  DeleteRuleProvider,
  FetchRuleProviderNow,
  GetRuleProviderItems,
  GetRuleProviders,
  UpdateRuleProvider,
} from '@/api/rule-providers'
import {
  CreateCustomOverride,
  DeleteCustomOverride,
  GetCustomOverrides,
  UpdateCustomOverride,
} from '@/api/custom-overrides'
import type { RouteMap } from '@/models/route-map'
import type {
  ProviderItem,
  RuleProvider,
  SaveRuleProviderRequest,
} from '@/models/rule-provider'
import type { CustomOverride, SaveCustomOverrideRequest } from '@/models/custom-override'
import RouteMapModal from '@/components/RouteMapModal.vue'
import { useAppMessage } from '@/composables/useAppMessage'

const message = useAppMessage()
const activeTab = ref<'maps' | 'providers' | 'overrides'>('maps')

// --- ROUTE MAPS ---
const maps = ref<RouteMap[]>([])
const loadingMaps = ref(false)
const searchMaps = ref('')
const showEditor = ref(false)
const selectedMap = ref<RouteMap | null>(null)

const routeMapSelectOptions = computed(() => [
  { title: 'Глобально (для всех клиентов)', value: null as string | null },
  ...maps.value.map(m => ({ title: `Профиль: ${m.name}`, value: m.id })),
])

const getRouteMapName = (routeMapId: string | null | undefined) => {
  if (!routeMapId) return 'Глобально'
  const found = maps.value.find(m => m.id === routeMapId)
  return found ? found.name : routeMapId.slice(0, 8)
}

const getActionColor = (action: string | undefined) => {
  if (action === 'block') return 'error'
  if (action === 'direct') return 'warning'
  return 'success'
}

const mapHeaders = [
  { title: 'Название карты', key: 'name', sortable: true },
  { title: 'Описание', key: 'description', sortable: true },
  { title: 'Действие по умолчанию', key: 'default_action', sortable: true, align: 'center' as const },
  { title: 'Кол-во правил', key: 'rules_count', sortable: true, align: 'center' as const },
  { title: 'Ревизия', key: 'revision', sortable: true, align: 'center' as const },
  { title: 'Статус', key: 'is_active', sortable: true, align: 'center' as const },
  { title: 'Действия', key: 'actions', sortable: false, align: 'center' as const },
]

const loadMaps = async () => {
  loadingMaps.value = true
  try {
    const rawMaps = await GetRouteMaps()
    maps.value = rawMaps.map(map => ({
      ...map,
      rules_count: map.rules.length,
    }))
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка загрузки карт маршрутизации'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  } finally {
    loadingMaps.value = false
  }
}

const openCreateMap = () => {
  selectedMap.value = null
  showEditor.value = true
}

const openEditMap = (map: RouteMap) => {
  selectedMap.value = map
  showEditor.value = true
}

const removeMap = async (id: string) => {
  if (!confirm('Вы уверены, что хотите удалить эту карту? Назначения пользователей также будут сброшены.')) return
  try {
    await DeleteRouteMap(id)
    message.success('Карта маршрутизации удалена')
    await loadMaps()
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка удаления карты'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
}

// --- RULE PROVIDERS (.ABC COMPILER) ---
const providers = ref<RuleProvider[]>([])
const loadingProviders = ref(false)
const searchProviders = ref('')
const showProviderModal = ref(false)
const fetchingProviderId = ref<string | null>(null)
const savingProvider = ref(false)
const providerError = ref('')

const providerForm = ref<SaveRuleProviderRequest>({
  name: '',
  description: '',
  provider_type: 'domain',
  format: 'plain',
  action: 'block',
  route_map_id: null,
  url: '',
  update_interval_hours: 24,
  is_active: true,
})
const editingProviderId = ref<string | null>(null)

const providerHeaders = [
  { title: 'Имя провайдера', key: 'name', sortable: true },
  { title: 'Тип', key: 'provider_type', sortable: true, align: 'center' as const },
  { title: 'Формат', key: 'format', sortable: true, align: 'center' as const },
  { title: 'Действие', key: 'action', sortable: true, align: 'center' as const },
  { title: 'Профиль', key: 'route_map_id', sortable: true, align: 'center' as const },
  { title: 'URL источника', key: 'url', sortable: false },
  { title: 'Интервал (ч)', key: 'update_interval_hours', sortable: true, align: 'center' as const },
  { title: 'Элементов в кэше (БД)', key: 'item_count', sortable: true, align: 'center' as const },
  { title: 'Последняя загрузка', key: 'last_fetched_at', sortable: true },
  { title: 'Статус', key: 'is_active', sortable: true, align: 'center' as const },
  { title: 'Действия', key: 'actions', sortable: false, align: 'center' as const },
]

const loadProviders = async () => {
  loadingProviders.value = true
  try {
    providers.value = await GetRuleProviders()
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка загрузки провайдеров'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  } finally {
    loadingProviders.value = false
  }
}

const openCreateProvider = () => {
  editingProviderId.value = null
  providerError.value = ''
  providerForm.value = {
    name: '',
    description: '',
    provider_type: 'domain',
    format: 'plain',
    action: 'block',
    route_map_id: null,
    url: '',
    update_interval_hours: 24,
    is_active: true,
  }
  showProviderModal.value = true
}

const openEditProvider = (p: RuleProvider) => {
  editingProviderId.value = p.id
  providerError.value = ''
  providerForm.value = {
    name: p.name,
    description: p.description,
    provider_type: p.provider_type,
    format: p.format,
    action: p.action || 'block',
    route_map_id: p.route_map_id ?? null,
    url: p.url,
    update_interval_hours: p.update_interval_hours,
    is_active: p.is_active,
  }
  showProviderModal.value = true
}

const saveProvider = async () => {
  if (!providerForm.value.name.trim() || !providerForm.value.url.trim()) {
    providerError.value = 'Пожалуйста, заполните название и URL'
    return
  }
  savingProvider.value = true
  providerError.value = ''
  try {
    if (editingProviderId.value) {
      await UpdateRuleProvider(editingProviderId.value, providerForm.value)
      message.success('Провайдер правил успешно обновлён')
    } else {
      await CreateRuleProvider(providerForm.value)
      message.success('Провайдер правил успешно создан')
    }
    showProviderModal.value = false
    await loadProviders()
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка сохранения провайдера'
    providerError.value = typeof msg === 'string' ? msg : JSON.stringify(msg)
    message.error(providerError.value)
  } finally {
    savingProvider.value = false
  }
}

const removeProvider = async (id: string) => {
  if (!confirm('Удалить этого провайдера правил?')) return
  try {
    await DeleteRuleProvider(id)
    message.success('Провайдер правил удалён')
    await loadProviders()
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка удаления провайдера'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
}

const fetchProviderNow = async (id: string) => {
  fetchingProviderId.value = id
  try {
    const updated = await FetchRuleProviderNow(id)
    message.success(`Правила загружены и сохранены в БД: ${updated.item_count} записей`)
    await loadProviders()
    if (inspectingProvider.value?.id === id) {
      inspectingProvider.value = updated
      await loadProviderItems()
    }
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка загрузки правил'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  } finally {
    fetchingProviderId.value = null
  }
}

// --- ПРОСМОТР КЭША ПРОВАЙДЕРА В ТАБЛИЦЕ БД ---
const showProviderItemsModal = ref(false)
const inspectingProvider = ref<RuleProvider | null>(null)
const providerItems = ref<ProviderItem[]>([])
const providerItemsTotal = ref(0)
const providerItemsPage = ref(1)
const providerItemsPerPage = ref(50)
const providerItemsSearch = ref('')
const loadingProviderItems = ref(false)

const providerItemHeaders = [
  { title: '# (ID в БД)', key: 'id', sortable: false, width: '130px' },
  { title: 'Загруженное правило (Домен / Подсеть)', key: 'rule_value', sortable: false },
]

const totalProviderPages = computed(() =>
  Math.max(1, Math.ceil(providerItemsTotal.value / providerItemsPerPage.value)),
)

const loadProviderItems = async () => {
  if (!inspectingProvider.value) return
  loadingProviderItems.value = true
  try {
    const res = await GetRuleProviderItems(inspectingProvider.value.id, {
      search: providerItemsSearch.value.trim() || undefined,
      page: providerItemsPage.value,
      per_page: providerItemsPerPage.value,
    })
    providerItems.value = res.items
    providerItemsTotal.value = res.total
  } catch (err: any) {
    const msg =
      err.response?.data?.message || err.response?.data || err.message || 'Ошибка загрузки кэша провайдера'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  } finally {
    loadingProviderItems.value = false
  }
}

const openProviderItemsModal = async (provider: RuleProvider) => {
  inspectingProvider.value = provider
  providerItemsPage.value = 1
  providerItemsSearch.value = ''
  showProviderItemsModal.value = true
  await loadProviderItems()
}

const onSearchProviderItems = async () => {
  providerItemsPage.value = 1
  await loadProviderItems()
}

// --- ADMIN CUSTOM OVERRIDES ---
const overrides = ref<CustomOverride[]>([])
const loadingOverrides = ref(false)
const searchOverrides = ref('')
const showOverrideModal = ref(false)
const editingOverrideId = ref<string | null>(null)
const savingOverride = ref(false)
const overrideError = ref('')

const overrideForm = ref<SaveCustomOverrideRequest>({
  route_map_id: null,
  rule_type: 'domain',
  pattern: '',
  category: 'block',
  comment: '',
  is_active: true,
})

const overrideHeaders = [
  { title: 'Шаблон / Паттерн', key: 'pattern', sortable: true },
  { title: 'Тип правила', key: 'rule_type', sortable: true, align: 'center' as const },
  { title: 'Категория (Действие)', key: 'category', sortable: true, align: 'center' as const },
  { title: 'Профиль', key: 'route_map_id', sortable: true, align: 'center' as const },
  { title: 'Комментарий', key: 'comment', sortable: false },
  { title: 'Статус', key: 'is_active', sortable: true, align: 'center' as const },
  { title: 'Создано', key: 'created_at', sortable: true },
  { title: 'Действия', key: 'actions', sortable: false, align: 'center' as const },
]

const loadOverrides = async () => {
  loadingOverrides.value = true
  try {
    overrides.value = await GetCustomOverrides()
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка загрузки исключений'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  } finally {
    loadingOverrides.value = false
  }
}

const openCreateOverride = () => {
  editingOverrideId.value = null
  overrideError.value = ''
  overrideForm.value = {
    route_map_id: null,
    rule_type: 'wildcard',
    pattern: '',
    category: 'block',
    comment: '',
    is_active: true,
  }
  showOverrideModal.value = true
}

const openEditOverride = (o: CustomOverride) => {
  editingOverrideId.value = o.id
  overrideError.value = ''
  overrideForm.value = {
    route_map_id: o.route_map_id,
    rule_type: o.rule_type,
    pattern: o.pattern,
    category: o.category,
    comment: o.comment,
    is_active: o.is_active,
  }
  showOverrideModal.value = true
}

const saveOverride = async () => {
  if (!overrideForm.value.pattern.trim()) {
    overrideError.value = 'Пожалуйста, введите шаблон домена или IP/CIDR'
    return
  }
  savingOverride.value = true
  overrideError.value = ''
  try {
    if (editingOverrideId.value) {
      await UpdateCustomOverride(editingOverrideId.value, overrideForm.value)
      message.success('Исключение успешно обновлено')
    } else {
      await CreateCustomOverride(overrideForm.value)
      message.success('Исключение успешно сохранено')
    }
    showOverrideModal.value = false
    await loadOverrides()
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка сохранения исключения'
    overrideError.value = typeof msg === 'string' ? msg : JSON.stringify(msg)
    message.error(overrideError.value)
  } finally {
    savingOverride.value = false
  }
}

const removeOverride = async (id: string) => {
  if (!confirm('Удалить это исключение?')) return
  try {
    await DeleteCustomOverride(id)
    message.success('Исключение удалено')
    await loadOverrides()
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка удаления исключения'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
}

onMounted(() => {
  loadMaps()
  loadProviders()
  loadOverrides()
})
</script>

<template>
  <v-container max-width="1400" class="route-maps-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-4">
      <v-list-item
        class="px-0"
        subtitle="Управление политиками Split Tunneling, компилятором правил (.abc) и AdBlock"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">Smart DNS & Маршрутизация</h1>
        </template>
      </v-list-item>
    </div>

    <v-tabs v-model="activeTab" color="primary" class="mb-5 border-b">
      <v-tab value="maps">
        <v-icon start icon="mdi-routes" />
        Карты маршрутизации
      </v-tab>
      <v-tab value="providers">
        <v-icon start icon="mdi-cloud-download" />
        Провайдеры правил (.abc)
      </v-tab>
      <v-tab value="overrides">
        <v-icon start icon="mdi-shield-edit" />
        Пользовательские исключения
      </v-tab>
    </v-tabs>

    <!-- TAB 1: ROUTE MAPS -->
    <v-window v-model="activeTab">
      <v-window-item value="maps">
        <div class="d-flex justify-space-between align-center mb-4">
          <v-text-field
            v-model="searchMaps"
            prepend-inner-icon="mdi-magnify"
            label="Поиск по картам..."
            variant="outlined"
            density="compact"
            hide-details
            single-line
            style="width: 280px"
          />
          <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreateMap">Создать карту</v-btn>
        </div>

        <v-data-table
          :headers="mapHeaders"
          :items="maps"
          :search="searchMaps"
          :loading="loadingMaps"
          density="comfortable"
          class="maps-table border rounded-lg"
          hover
          @click:row="(_: unknown, data: { item: RouteMap }) => openEditMap(data.item)"
        >
          <template #item.name="{ item }">
            <span class="font-weight-bold">{{ item.name }}</span>
          </template>
          <template #item.default_action="{ item }">
            <v-chip :color="item.default_action === 'tunnel' ? 'success' : 'warning'" size="small">
              {{ item.default_action.toUpperCase() }}
            </v-chip>
          </template>
          <template #item.rules_count="{ item }">
            <span class="font-weight-bold">{{ item.rules_count }}</span>
          </template>
          <template #item.is_active="{ item }">
            <v-chip :color="item.is_active ? 'success' : 'default'" size="small">
              {{ item.is_active ? 'ACTIVE' : 'DISABLED' }}
            </v-chip>
          </template>
          <template #item.actions="{ item }">
            <v-btn color="error" variant="text" size="small" @click.stop="removeMap(item.id)">
              Удалить
            </v-btn>
          </template>
        </v-data-table>
      </v-window-item>

      <!-- TAB 2: RULE PROVIDERS (.ABC) -->
      <v-window-item value="providers">
        <div class="d-flex justify-space-between align-center mb-4">
          <v-text-field
            v-model="searchProviders"
            prepend-inner-icon="mdi-magnify"
            label="Поиск провайдеров..."
            variant="outlined"
            density="compact"
            hide-details
            single-line
            style="width: 280px"
          />
          <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreateProvider">Добавить провайдер</v-btn>
        </div>

        <v-data-table
          :headers="providerHeaders"
          :items="providers"
          :search="searchProviders"
          :loading="loadingProviders"
          density="comfortable"
          class="border rounded-lg"
        >
          <template #item.name="{ item }">
            <span class="font-weight-bold">{{ item.name }}</span>
            <div class="text-caption text-medium-emphasis">{{ item.description }}</div>
          </template>
          <template #item.provider_type="{ item }">
            <v-chip size="small" :color="item.provider_type === 'domain' ? 'info' : 'primary'">
              {{ item.provider_type.toUpperCase() }}
            </v-chip>
          </template>
          <template #item.format="{ item }">
            <v-chip size="small" variant="outlined">
              {{ item.format }}
            </v-chip>
          </template>
          <template #item.action="{ item }">
            <v-chip size="small" :color="getActionColor(item.action)">
              {{ (item.action || 'block').toUpperCase() }}
            </v-chip>
          </template>
          <template #item.route_map_id="{ item }">
            <v-chip size="small" :variant="item.route_map_id ? 'tonal' : 'outlined'" color="secondary">
              {{ getRouteMapName(item.route_map_id) }}
            </v-chip>
          </template>
          <template #item.url="{ item }">
            <span class="text-truncate d-inline-block" style="max-width: 240px" :title="item.url">{{
              item.url
            }}</span>
          </template>
          <template #item.item_count="{ item }">
            <v-chip
              size="small"
              color="success"
              variant="tonal"
              prepend-icon="mdi-table-eye"
              class="cursor-pointer"
              title="Нажмите для просмотра таблицы загруженных правил"
              @click="openProviderItemsModal(item)"
            >
              {{ item.item_count.toLocaleString() }}
            </v-chip>
          </template>
          <template #item.last_fetched_at="{ item }">
            <span class="text-caption">{{ item.last_fetched_at || 'Никогда' }}</span>
          </template>
          <template #item.is_active="{ item }">
            <v-chip :color="item.is_active ? 'success' : 'default'" size="small">
              {{ item.is_active ? 'ACTIVE' : 'OFF' }}
            </v-chip>
          </template>
          <template #item.actions="{ item }">
            <div class="d-flex ga-1 justify-center">
              <v-btn
                icon="mdi-table-eye"
                size="small"
                variant="text"
                color="info"
                title="Просмотреть загруженные данные в кэше БД"
                @click="openProviderItemsModal(item)"
              />
              <v-btn
                icon="mdi-sync"
                size="small"
                variant="text"
                color="primary"
                :loading="fetchingProviderId === item.id"
                title="Принудительно скачать и обновить кэш в БД"
                @click="fetchProviderNow(item.id)"
              />
              <v-btn
                icon="mdi-pencil"
                size="small"
                variant="text"
                title="Редактировать провайдер"
                @click="openEditProvider(item)"
              />
              <v-btn
                icon="mdi-delete"
                size="small"
                variant="text"
                color="error"
                title="Удалить провайдер"
                @click="removeProvider(item.id)"
              />
            </div>
          </template>
        </v-data-table>
      </v-window-item>

      <!-- TAB 3: CUSTOM OVERRIDES -->
      <v-window-item value="overrides">
        <div class="d-flex justify-space-between align-center mb-4">
          <v-text-field
            v-model="searchOverrides"
            prepend-inner-icon="mdi-magnify"
            label="Поиск исключений..."
            variant="outlined"
            density="compact"
            hide-details
            single-line
            style="width: 280px"
          />
          <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreateOverride">Добавить исключение</v-btn>
        </div>

        <v-data-table
          :headers="overrideHeaders"
          :items="overrides"
          :search="searchOverrides"
          :loading="loadingOverrides"
          density="comfortable"
          class="border rounded-lg"
        >
          <template #item.pattern="{ item }">
            <code class="font-weight-bold text-primary">{{ item.pattern }}</code>
          </template>
          <template #item.rule_type="{ item }">
            <v-chip size="small" variant="outlined">{{ item.rule_type }}</v-chip>
          </template>
          <template #item.category="{ item }">
            <v-chip size="small" :color="getActionColor(item.category)">
              {{ item.category.toUpperCase() }}
            </v-chip>
          </template>
          <template #item.route_map_id="{ item }">
            <v-chip size="small" :variant="item.route_map_id ? 'tonal' : 'outlined'" color="secondary">
              {{ getRouteMapName(item.route_map_id) }}
            </v-chip>
          </template>
          <template #item.is_active="{ item }">
            <v-chip :color="item.is_active ? 'success' : 'default'" size="small">
              {{ item.is_active ? 'ON' : 'OFF' }}
            </v-chip>
          </template>
          <template #item.actions="{ item }">
            <div class="d-flex ga-1 justify-center">
              <v-btn icon="mdi-pencil" size="small" variant="text" @click="openEditOverride(item)" />
              <v-btn icon="mdi-delete" size="small" variant="text" color="error" @click="removeOverride(item.id)" />
            </div>
          </template>
        </v-data-table>
      </v-window-item>
    </v-window>

    <!-- MODAL: ROUTE MAP -->
    <RouteMapModal
      v-model="showEditor"
      :route-map="selectedMap"
      :providers="providers"
      @saved="loadMaps"
    />

    <!-- MODAL: RULE PROVIDER CREATE / EDIT -->
    <v-dialog v-model="showProviderModal" max-width="640">
      <v-card>
        <v-card-title>
          {{ editingProviderId ? 'Редактировать провайдер правил' : 'Добавить провайдер правил' }}
        </v-card-title>
        <v-card-text>
          <v-alert
            v-if="providerError"
            type="error"
            variant="tonal"
            class="mb-3"
            closable
            @click:close="providerError = ''"
          >
            {{ providerError }}
          </v-alert>
          <v-text-field
            v-model="providerForm.name"
            label="Название (например, Anti-AD или Banks RU)"
            variant="outlined"
            class="mb-3"
          />
          <v-text-field v-model="providerForm.description" label="Описание" variant="outlined" class="mb-3" />
          <v-text-field
            v-model="providerForm.url"
            label="URL списка правил (.list / .txt)"
            variant="outlined"
            class="mb-3"
          />
          <v-row class="mb-1">
            <v-col cols="12" sm="6">
              <v-select
                v-model="providerForm.provider_type"
                :items="[
                  { title: 'Домены (GeoSite)', value: 'domain' },
                  { title: 'IP / CIDR (GeoIP)', value: 'ip' },
                ]"
                label="Тип списка"
                variant="outlined"
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-select
                v-model="providerForm.format"
                :items="[
                  { title: 'Простой список (plain)', value: 'plain' },
                  { title: 'V2Ray / Clash (+.)', value: 'v2ray' },
                  { title: 'CIDR список', value: 'cidr' },
                ]"
                label="Формат"
                variant="outlined"
              />
            </v-col>
          </v-row>
          <v-row class="mb-1">
            <v-col cols="12" sm="6">
              <v-select
                v-model="providerForm.action"
                :items="[
                  { title: 'Заблокировать (BLOCK — AdBlock 0.0.0.0)', value: 'block' },
                  { title: 'В обход VPN (DIRECT — Split Tunneling)', value: 'direct' },
                  { title: 'В туннель VPN (PROXY)', value: 'proxy' },
                ]"
                label="Действие для списка (Action)"
                variant="outlined"
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-select
                v-model="providerForm.route_map_id"
                :items="routeMapSelectOptions"
                item-title="title"
                item-value="value"
                label="Применить к профилю"
                variant="outlined"
              />
            </v-col>
          </v-row>
          <v-text-field
            v-model.number="providerForm.update_interval_hours"
            type="number"
            label="Интервал автообновления (в часах)"
            variant="outlined"
            class="mb-3"
          />
          <v-switch v-model="providerForm.is_active" label="Активен" color="primary" hide-details />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" :disabled="savingProvider" @click="showProviderModal = false">Отмена</v-btn>
          <v-btn color="primary" :loading="savingProvider" @click="saveProvider">Сохранить</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- MODAL: RULE PROVIDER CACHED ITEMS TABLE -->
    <v-dialog v-model="showProviderItemsModal" max-width="820">
      <v-card v-if="inspectingProvider">
        <v-card-title class="d-flex justify-space-between align-center flex-wrap ga-2">
          <div>
            <span>Кэш провайдера: {{ inspectingProvider.name }}</span>
            <div class="text-caption text-medium-emphasis">
              Таблица <code>rule_provider_items</code> · Всего в кэше:
              <strong>{{ providerItemsTotal.toLocaleString() }}</strong> записей · Действие:
              <strong>{{ (inspectingProvider.action || 'block').toUpperCase() }}</strong>
            </div>
          </div>
          <v-btn
            color="primary"
            variant="tonal"
            size="small"
            prepend-icon="mdi-sync"
            :loading="fetchingProviderId === inspectingProvider.id"
            @click="fetchProviderNow(inspectingProvider.id)"
          >
            Обновить из источника
          </v-btn>
        </v-card-title>

        <v-card-text>
          <div class="d-flex ga-2 mb-3">
            <v-text-field
              v-model="providerItemsSearch"
              prepend-inner-icon="mdi-magnify"
              label="Фильтр по домену или CIDR (нажмите Enter)..."
              variant="outlined"
              density="compact"
              hide-details
              clearable
              @keyup.enter="onSearchProviderItems"
              @click:clear="onSearchProviderItems"
            />
            <v-btn color="primary" variant="flat" @click="onSearchProviderItems">Найти</v-btn>
          </div>

          <v-data-table
            :headers="providerItemHeaders"
            :items="providerItems"
            :loading="loadingProviderItems"
            :items-per-page="providerItemsPerPage"
            density="compact"
            class="border rounded-lg"
            hide-default-footer
          >
            <template #item.id="{ item }">
              <span class="text-caption text-medium-emphasis">#{{ item.id }}</span>
            </template>
            <template #item.rule_value="{ item }">
              <code class="text-body-2">{{ item.rule_value }}</code>
            </template>
            <template #no-data>
              <div class="py-6 text-center text-medium-emphasis">
                В таблице <code>rule_provider_items</code> пока нет записей для этого провайдера. Нажмите
                «Обновить из источника».
              </div>
            </template>
          </v-data-table>

          <div v-if="totalProviderPages > 1" class="d-flex justify-center mt-4">
            <v-pagination
              v-model="providerItemsPage"
              :length="totalProviderPages"
              :total-visible="7"
              density="comfortable"
              @update:model-value="loadProviderItems"
            />
          </div>
        </v-card-text>

        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="showProviderItemsModal = false">Закрыть</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- MODAL: CUSTOM OVERRIDE -->
    <v-dialog v-model="showOverrideModal" max-width="640">
      <v-card>
        <v-card-title>
          {{ editingOverrideId ? 'Редактировать исключение' : 'Добавить исключение (Override)' }}
        </v-card-title>
        <v-card-text>
          <v-alert
            v-if="overrideError"
            type="error"
            variant="tonal"
            class="mb-3"
            closable
            @click:close="overrideError = ''"
          >
            {{ overrideError }}
          </v-alert>
          <v-text-field
            v-model="overrideForm.pattern"
            label="Шаблон (например, corp.internal, *.bank.ru, 192.168.0.0/16)"
            variant="outlined"
            class="mb-3"
          />
          <v-row class="mb-1">
            <v-col cols="12" sm="6">
              <v-select
                v-model="overrideForm.rule_type"
                :items="[
                  { title: 'Точный домен (Domain)', value: 'domain' },
                  { title: 'Поддомены (*.wildcard)', value: 'wildcard' },
                  { title: 'IP / Подсеть (CIDR)', value: 'cidr' },
                ]"
                label="Тип совпадения"
                variant="outlined"
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-select
                v-model="overrideForm.category"
                :items="[
                  { title: 'Заблокировать (custom_block)', value: 'block' },
                  { title: 'В обход VPN (custom_direct)', value: 'direct' },
                  { title: 'В туннель (custom_proxy)', value: 'proxy' },
                ]"
                label="Действие"
                variant="outlined"
              />
            </v-col>
          </v-row>
          <v-select
            v-model="overrideForm.route_map_id"
            :items="routeMapSelectOptions"
            item-title="title"
            item-value="value"
            label="Применить к профилю"
            variant="outlined"
            class="mb-3"
          />
          <v-text-field v-model="overrideForm.comment" label="Комментарий / Заметка" variant="outlined" class="mb-3" />
          <v-switch v-model="overrideForm.is_active" label="Активно" color="primary" hide-details />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" :disabled="savingOverride" @click="showOverrideModal = false">Отмена</v-btn>
          <v-btn color="primary" :loading="savingOverride" @click="saveOverride">Сохранить</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<style scoped>
.route-maps-page {
  padding: 24px;
}
.maps-table :deep(tbody tr) {
  cursor: pointer;
}
.maps-table :deep(tbody tr:hover) {
  background: rgba(43, 184, 148, 0.07) !important;
}
.cursor-pointer {
  cursor: pointer;
}
</style>
