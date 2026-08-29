<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { DeleteRouteMap, GetRouteMaps } from '@/api/route-maps'
import type { RouteMap } from '@/models/route-map'
import RouteMapModal from '@/components/RouteMapModal.vue'

const maps = ref<RouteMap[]>([])
const loading = ref(false)
const searchQuery = ref('')

const showEditor = ref(false)
const selectedMap = ref<RouteMap | null>(null)

const headers = [
  { title: 'Название карты', key: 'name', sortable: true },
  { title: 'Описание', key: 'description', sortable: true },
  { title: 'Действие по умолчанию', key: 'default_action', sortable: true, align: 'center' as const },
  { title: 'Кол-во правил', key: 'rules_count', sortable: true, align: 'center' as const },
  { title: 'Ревизия', key: 'revision', sortable: true, align: 'center' as const },
  { title: 'Статус', key: 'is_active', sortable: true, align: 'center' as const },
  { title: 'Действия', key: 'actions', sortable: false, align: 'center' as const },
]

const load = async () => {
  loading.value = true
  try {
    const rawMaps = await GetRouteMaps()
    maps.value = rawMaps.map(map => ({
      ...map,
      rules_count: map.rules.length, // Поле для удобной сортировки в таблице
    }))
  } finally {
    loading.value = false
  }
}

const openCreate = () => {
  selectedMap.value = null
  showEditor.value = true
}

const openEdit = (map: RouteMap) => {
  selectedMap.value = map
  showEditor.value = true
}

const remove = async (id: string) => {
  if (!confirm('Вы уверены, что хотите удалить эту карту? Назначения пользователей также будут сброшены.')) return
  await DeleteRouteMap(id)
  await load()
}

onMounted(load)
</script>

<template>
  <v-container max-width="1400" class="route-maps-page">
    <div class="d-flex justify-space-between align-center flex-wrap ga-4 mb-5">
      <v-list-item
          class="px-0"
          subtitle="Политики split tunneling для клиентских конфигураций"
      >
        <template #title>
          <h1 class="text-h5 font-weight-bold">Route Maps</h1>
        </template>
      </v-list-item>
      <div class="d-flex align-center ga-3">
        <v-text-field
            v-model="searchQuery"
            prepend-inner-icon="mdi-magnify"
            label="Поиск по картам..."
            variant="outlined"
            density="compact"
            hide-details
            single-line
            style="width: 280px"
        />
        <v-btn color="primary" @click="openCreate">Создать карту</v-btn>
      </div>
    </div>

    <v-data-table
        :headers="headers"
        :items="maps"
        :search="searchQuery"
        :loading="loading"
        :items-per-page="10"
        :items-per-page-options="[10, 20, 50]"
        items-per-page-text="Строк на странице"
        loading-text="Загрузка карт маршрутизации…"
        no-data-text="Карт маршрутизации пока нет — создайте первую!"
        density="comfortable"
        class="maps-table border rounded-lg"
        hover
        @click:row="(_: unknown, data: { item: RouteMap }) => openEdit(data.item)"
    >
      <template #item.name="{ item }">
        <span class="map-name-col">{{ item.name }}</span>
      </template>

      <template #item.description="{ item }">
        <span class="text-caption text-medium-emphasis">{{ item.description || '—' }}</span>
      </template>

      <template #item.default_action="{ item }">
        <v-chip :color="item.default_action === 'tunnel' ? 'success' : 'warning'" size="small">
          {{ item.default_action.toUpperCase() }}
        </v-chip>
      </template>

      <template #item.rules_count="{ item }">
        <span class="font-weight-bold">{{ item.rules_count }}</span>
      </template>

      <template #item.revision="{ item }">
        <v-chip size="small" variant="outlined">rev {{ item.revision }}</v-chip>
      </template>

      <template #item.is_active="{ item }">
        <v-chip :color="item.is_active ? 'success' : 'default'" size="small">
          {{ item.is_active ? 'ACTIVE' : 'DISABLED' }}
        </v-chip>
      </template>

      <template #item.actions="{ item }">
        <v-btn color="error" variant="text" size="small" @click.stop="remove(item.id)">
          Удалить
        </v-btn>
      </template>
    </v-data-table>

    <RouteMapModal
        v-model="showEditor"
        :route-map="selectedMap"
        @saved="load"
    />
  </v-container>
</template>

<style scoped>
.route-maps-page { padding: 24px; }
.maps-table :deep(tbody tr) { cursor: pointer; }
.maps-table :deep(tbody tr:hover) { background: rgba(43, 184, 148, .07) !important; }
.map-name-col { font-weight: 600; font-size: 15px; }
</style>