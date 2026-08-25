<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { DeleteRouteMap, GetRouteMaps } from '@/api/route-maps'
import type { RouteMap } from '@/models/route-map'
import RouteMapModal from '@/components/RouteMapModal.vue'

const maps = ref<RouteMap[]>([])
const loading = ref(false)

const showEditor = ref(false)
const selectedMap = ref<RouteMap | null>(null)

const load = async () => {
  loading.value = true
  try {
    maps.value = await GetRouteMaps()
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
  if (!confirm('Вы уверены, что хотите удалить эту карту? Назначения пользователей также будут удалены.')) return
  await DeleteRouteMap(id)
  await load()
}

onMounted(load)
</script>

<template>
  <main class="route-page">
    <div class="d-flex justify-space-between align-center page-title">
      <div>
        <h2>Route Maps</h2>
        <span>Политики split tunneling для клиентских конфигураций</span>
      </div>
      <v-btn color="primary" @click="openCreate">Создать карту</v-btn>
    </div>

    <v-alert type="info" variant="tonal" class="mb-6">
      CIDR-карты работают на desktop и mobile. Application rules используют Windows per-app filtering.
      Domain/Geo и межузловые hops появятся вместе с соответствующим data plane.
    </v-alert>

    <div class="position-relative">
      <v-row v-if="maps.length > 0">
        <v-col v-for="map in maps" :key="map.id" cols="12" md="6">
          <v-card hover class="pa-4 h-100 cursor-pointer d-flex flex-column" @click="openEdit(map)">
            <div class="d-flex justify-space-between align-start mb-3">
              <div>
                <div class="d-flex align-center gap-2 mb-1">
                  <strong class="text-h6">{{ map.name }}</strong>
                  <v-chip :color="map.is_active ? 'success' : 'default'" size="small">
                    {{ map.is_active ? 'ACTIVE' : 'DISABLED' }}
                  </v-chip>
                  <v-chip size="small" variant="outlined">rev {{ map.revision }}</v-chip>
                </div>
                <div class="text-medium-emphasis text-body-2 mt-1">
                  {{ map.description || 'Без описания' }}
                </div>
              </div>
              <div class="d-flex flex-column align-end gap-2">
                <span class="text-caption text-medium-emphasis">
                  Rules: {{ map.rules.length }}
                </span>
                <v-chip :color="map.default_action === 'tunnel' ? 'success' : 'warning'" size="small">
                  default: {{ map.default_action }}
                </v-chip>
                <v-btn color="error" variant="text" size="small" class="mt-2" @click.stop="remove(map.id)">
                  Удалить
                </v-btn>
              </div>
            </div>
          </v-card>
        </v-col>
      </v-row>

      <v-empty-state
          v-else
          title="Маршрутных карт ещё нет"
          text="Создайте первую карту для настройки split tunneling."
          class="mt-10"
      />
    </div>

    <!-- Модалка редактирования -->
    <RouteMapModal
        v-model="showEditor"
        :route-map="selectedMap"
        @saved="load"
    />
  </main>
</template>

<style scoped>
.route-page { max-width: 1200px; margin: 0 auto; padding: 24px; }
.page-title { margin-bottom: 24px; }
.page-title h2 { margin: 0 0 4px; font-weight: 600; font-size: 22px; }
.page-title span { color: #94a3b8; font-size: 13px; }
.gap-2 { gap: 8px; }
</style>
