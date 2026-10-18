<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { DeleteRouteMap, GetRouteMaps } from '@/api/route-maps'
import {
  CreateRuleProvider,
  DeleteRuleProvider,
  FetchRuleProviderNow,
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
import type { RuleProvider, SaveRuleProviderRequest } from '@/models/rule-provider'
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
  url: '',
  update_interval_hours: 24,
  is_active: true,
})
const editingProviderId = ref<string | null>(null)

const providerHeaders = [
  { title: 'Имя провайдера', key: 'name', sortable: true },
  { title: 'Тип', key: 'provider_type', sortable: true, align: 'center' as const },
  { title: 'Формат', key: 'format', sortable: true, align: 'center' as const },
  { title: 'URL источника', key: 'url', sortable: false },
  { title: 'Интервал (ч)', key: 'update_interval_hours', sortable: true, align: 'center' as const },
  { title: 'Элементов в кэше', key: 'item_count', sortable: true, align: 'center' as const },
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
    message.success(`Правила загружены: ${updated.item_count} записей`)
    await loadProviders()
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка загрузки правил'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  } finally {
    fetchingProviderId.value = null
  }
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
  { title: 'Категория', key: 'category', sortable: true, align: 'center' as const },
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
          <template #item.url="{ item }">
            <span class="text-truncate d-inline-block" style="max-width: 280px;" :title="item.url">{{ item.url }}</span>
          </template>
          <template #item.item_count="{ item }">
            <v-chip size="small" color="success" variant="tonal">{{ item.item_count.toLocaleString() }}</v-chip>
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
                icon="mdi-sync"
                size="small"
                variant="text"
                color="primary"
                :loading="fetchingProviderId === item.id"
                title="Обновить сейчас"
                @click="fetchProviderNow(item.id)"
              />
              <v-btn
                icon="mdi-pencil"
                size="small"
                variant="text"
                @click="openEditProvider(item)"
              />
              <v-btn
                icon="mdi-delete"
                size="small"
                variant="text"
                color="error"
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
            <v-chip
              size="small"
              :color="item.category === 'block' ? 'error' : item.category === 'direct' ? 'warning' : 'success'"
            >
              {{ item.category.toUpperCase() }}
            </v-chip>
          </template>
          <template #item.is_active="{ item }">
            <v-chip :color="item.is_active ? 'success' : 'default'" size="small">
              {{ item.is_active ? 'ON' : 'OFF' }}
            </v-chip>
          </template>
          <template #item.actions="{ item }">
            <div class="d-flex ga-1 justify-center">
              <v-btn
                icon="mdi-pencil"
                size="small"
                variant="text"
                @click="openEditOverride(item)"
              />
              <v-btn
                icon="mdi-delete"
                size="small"
                variant="text"
                color="error"
                @click="removeOverride(item.id)"
              />
            </div>
          </template>
        </v-data-table>
      </v-window-item>
    </v-window>

    <!-- MODAL: ROUTE MAP -->
    <RouteMapModal
      v-model="showEditor"
      :route-map="selectedMap"
      @saved="loadMaps"
    />

    <!-- MODAL: RULE PROVIDER -->
    <v-dialog v-model="showProviderModal" max-width="600">
      <v-card>
        <v-card-title>
          {{ editingProviderId ? 'Редактировать провайдер правил' : 'Добавить провайдер правил' }}
        </v-card-title>
        <v-card-text>
          <v-alert v-if="providerError" type="error" variant="tonal" class="mb-3" closable @click:close="providerError = ''">
            {{ providerError }}
          </v-alert>
          <v-text-field v-model="providerForm.name" label="Название (например, Anti-AD)" variant="outlined" class="mb-3" />
          <v-text-field v-model="providerForm.description" label="Описание" variant="outlined" class="mb-3" />
          <v-text-field v-model="providerForm.url" label="URL списка правил (.list / .txt)" variant="outlined" class="mb-3" />
          <v-row class="mb-1">
            <v-col cols="6">
              <v-select
                v-model="providerForm.provider_type"
                :items="[{ title: 'Домены (GeoSite)', value: 'domain' }, { title: 'IP / CIDR (GeoIP)', value: 'ip' }]"
                label="Тип списка"
                variant="outlined"
              />
            </v-col>
            <v-col cols="6">
              <v-select
                v-model="providerForm.format"
                :items="[{ title: 'Простой список (plain)', value: 'plain' }, { title: 'V2Ray / Clash (+.)', value: 'v2ray' }, { title: 'CIDR список', value: 'cidr' }]"
                label="Формат"
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

    <!-- MODAL: CUSTOM OVERRIDE -->
    <v-dialog v-model="showOverrideModal" max-width="600">
      <v-card>
        <v-card-title>
          {{ editingOverrideId ? 'Редактировать исключение' : 'Добавить исключение (Override)' }}
        </v-card-title>
        <v-card-text>
          <v-alert v-if="overrideError" type="error" variant="tonal" class="mb-3" closable @click:close="overrideError = ''">
            {{ overrideError }}
          </v-alert>
          <v-text-field
            v-model="overrideForm.pattern"
            label="Шаблон (например, corp.internal, *.bank.ru, 192.168.0.0/16)"
            variant="outlined"
            class="mb-3"
          />
          <v-row class="mb-1">
            <v-col cols="6">
              <v-select
                v-model="overrideForm.rule_type"
                :items="[
                  { title: 'Точный домен (Domain)', value: 'domain' },
                  { title: 'Поддомены (*.wildcard)', value: 'wildcard' },
                  { title: 'IP / Подсеть (CIDR)', value: 'cidr' }
                ]"
                label="Тип совпадения"
                variant="outlined"
              />
            </v-col>
            <v-col cols="6">
              <v-select
                v-model="overrideForm.category"
                :items="[
                  { title: 'Заблокировать (custom_block)', value: 'block' },
                  { title: 'В обход VPN (custom_direct)', value: 'direct' },
                  { title: 'В туннель (custom_proxy)', value: 'proxy' }
                ]"
                label="Действие"
                variant="outlined"
              />
            </v-col>
          </v-row>
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
.route-maps-page { padding: 24px; }
.maps-table :deep(tbody tr) { cursor: pointer; }
.maps-table :deep(tbody tr:hover) { background: rgba(43, 184, 148, .07) !important; }
</style>
