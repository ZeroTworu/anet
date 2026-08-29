<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { DeleteRouteMap, GetRouteMaps } from '@/api/route-maps'
import type { RouteMap } from '@/models/route-map'
import RouteMapModal from '@/components/RouteMapModal.vue'
import EntityCard from '@/components/EntityCard.vue'

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
  <v-container max-width="1200" class="route-maps-page">
    <div class="d-flex justify-space-between align-center mb-5">
      <div>
        <h2 class="text-h6 font-weight-bold ma-0">Route Maps</h2>
        <span class="text-caption text-medium-emphasis">Политики split tunneling для клиентских конфигураций</span>
      </div>
      <v-btn color="primary" @click="openCreate">Создать карту</v-btn>
    </div>

    <div class="position-relative">
      <v-row v-if="maps.length > 0">
        <v-col v-for="map in maps" :key="map.id" cols="12" md="6">
          <EntityCard
              :title="map.name"
              :subtitle="map.description || 'Без описания'"
              @click="openEdit(map)"
          >
            <template #badges>
              <v-chip :color="map.is_active ? 'success' : 'default'" size="small">
                {{ map.is_active ? 'ACTIVE' : 'DISABLED' }}
              </v-chip>
              <v-chip size="small" variant="outlined">rev {{ map.revision }}</v-chip>
            </template>

            <template #meta>
              <span class="text-caption text-medium-emphasis">Rules: {{ map.rules.length }}</span>
              <v-chip :color="map.default_action === 'tunnel' ? 'success' : 'warning'" size="small">
                default: {{ map.default_action }}
              </v-chip>
              <v-btn color="error" variant="text" size="small" @click.stop="remove(map.id)">
                Удалить
              </v-btn>
            </template>
          </EntityCard>
        </v-col>
      </v-row>

      <v-empty-state
          v-else
          title="Маршрутных карт ещё нет"
          text="Создайте первую карту для настройки split tunneling."
          class="mt-10"
      />
    </div>

    <RouteMapModal
        v-model="showEditor"
        :route-map="selectedMap"
        @saved="load"
    />
  </v-container>
</template>

<style scoped>
.route-maps-page { padding: 24px; }
</style>
