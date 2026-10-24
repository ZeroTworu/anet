<script setup lang="ts">
import { ref, watch } from 'vue'
import {
  CreateDohResolver,
  DeleteDohResolver,
  UpdateDohResolver,
} from '@/api/doh-resolvers'
import type { DohResolver, SaveDohResolverRequest } from '@/models/doh-resolver'
import { useDohResolvers } from '@/utils/doh'
import { useAppMessage } from '@/composables/useAppMessage'

const show = defineModel<boolean>()

const emit = defineEmits<{
  (e: 'updated'): void
}>()

const message = useAppMessage()
const { resolvers, loading, reloadResolvers } = useDohResolvers()

const saving = ref(false)
const editingId = ref<string | null>(null)

const form = ref<SaveDohResolverRequest>({
  name: '',
  url: '',
  is_default: false,
  is_active: true,
})

const resetForm = () => {
  editingId.value = null
  form.value = {
    name: '',
    url: '',
    is_default: false,
    is_active: true,
  }
}

watch(
  () => show.value,
  (isOpen) => {
    if (isOpen) {
      resetForm()
      reloadResolvers()
    }
  },
  { immediate: true },
)

const startEdit = (item: DohResolver) => {
  editingId.value = item.id
  form.value = {
    name: item.name,
    url: item.url,
    is_default: item.is_default,
    is_active: item.is_active,
  }
}

const save = async () => {
  const url = form.value.url.trim()
  if (!url.startsWith('https://') && !url.startsWith('http://')) {
    message.error('URL резолвера должен начинаться с https:// или http://')
    return
  }

  saving.value = true
  try {
    const payload: SaveDohResolverRequest = {
      name: form.value.name.trim() || url,
      url,
      is_default: form.value.is_default,
      is_active: form.value.is_active,
    }
    if (editingId.value) {
      await UpdateDohResolver(editingId.value, payload)
      message.success('DoH-резолвер обновлён')
    } else {
      await CreateDohResolver(payload)
      message.success('DoH-резолвер добавлен в БД')
    }
    resetForm()
    await reloadResolvers()
    emit('updated')
  } catch (err: any) {
    const msg = err.response?.data?.message || err.response?.data || err.message || 'Ошибка сохранения DoH-резолвера'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  } finally {
    saving.value = false
  }
}

const toggleFlag = async (item: DohResolver, field: 'is_default' | 'is_active') => {
  try {
    await UpdateDohResolver(item.id, {
      name: item.name,
      url: item.url,
      is_default: field === 'is_default' ? !item.is_default : item.is_default,
      is_active: field === 'is_active' ? !item.is_active : item.is_active,
    })
    await reloadResolvers()
    emit('updated')
  } catch (err: any) {
    const msg = err.response?.data || err.message || 'Ошибка обновления статуса'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
}

const remove = async (item: DohResolver) => {
  if (!confirm(`Удалить резолвер "${item.name}" (${item.url}) из БД?`)) return
  try {
    await DeleteDohResolver(item.id)
    message.success('DoH-резолвер удалён')
    if (editingId.value === item.id) {
      resetForm()
    }
    await reloadResolvers()
    emit('updated')
  } catch (err: any) {
    const msg = err.response?.data || err.message || 'Ошибка удаления резолвера'
    message.error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
}
</script>

<template>
  <v-dialog v-model="show" max-width="760px">
    <v-card>
      <v-card-title class="d-flex justify-space-between align-center pb-2">
        <div>
          <div class="text-h6">Справочник публичных DoH-резолверов (БД)</div>
          <div class="text-caption text-medium-emphasis">
            Таблица <code>doh_resolvers</code> — используется в выпадающих списках и при автогенерации <code>?resolver=...</code>
          </div>
        </div>
        <v-btn icon="mdi-close" variant="text" size="small" @click="show = false" />
      </v-card-title>

      <v-card-text>
        <v-sheet color="surface-variant" rounded="lg" border class="pa-3 mb-4">
          <div class="text-subtitle-2 font-weight-bold mb-2">
            {{ editingId ? 'Редактировать резолвер' : 'Добавить новый DoH-резолвер' }}
          </div>
          <v-row dense align="center">
            <v-col cols="12" sm="4">
              <v-text-field
                v-model="form.name"
                label="Название (напр. Yandex Safe DNS)"
                placeholder="Yandex Safe DNS"
                density="compact"
                variant="outlined"
                hide-details
              />
            </v-col>
            <v-col cols="12" sm="8">
              <v-text-field
                v-model="form.url"
                label="URL эндпоинта (?resolver=...)"
                placeholder="https://77.88.8.7/dns-query"
                density="compact"
                variant="outlined"
                hide-details
              />
            </v-col>
            <v-col cols="12" sm="4" class="mt-2">
              <v-checkbox
                v-model="form.is_default"
                label="Подставлять по умолчанию"
                density="compact"
                color="primary"
                hide-details
              />
            </v-col>
            <v-col cols="12" sm="3" class="mt-2">
              <v-checkbox
                v-model="form.is_active"
                label="Активен"
                density="compact"
                color="success"
                hide-details
              />
            </v-col>
            <v-col cols="12" sm="5" class="mt-2 d-flex justify-end ga-2">
              <v-btn v-if="editingId" variant="text" size="small" @click="resetForm">
                Отмена
              </v-btn>
              <v-btn
                color="primary"
                variant="flat"
                size="small"
                prepend-icon="mdi-content-save"
                :loading="saving"
                :disabled="!form.url.trim()"
                @click="save"
              >
                {{ editingId ? 'Обновить' : 'Добавить' }}
              </v-btn>
            </v-col>
          </v-row>
        </v-sheet>

        <v-table density="comfortable" class="border rounded-lg">
          <thead>
            <tr>
              <th>Название</th>
              <th>URL резолвера</th>
              <th class="text-center">По умолчанию</th>
              <th class="text-center">Статус</th>
              <th class="text-center" style="width: 110px">Действия</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading && !resolvers.length">
              <td colspan="5" class="text-center py-4 text-medium-emphasis">Загрузка из БД...</td>
            </tr>
            <tr v-else-if="!resolvers.length">
              <td colspan="5" class="text-center py-4 text-medium-emphasis">
                В таблице <code>doh_resolvers</code> пока нет записей
              </td>
            </tr>
            <tr v-for="item in resolvers" :key="item.id">
              <td class="font-weight-medium">{{ item.name }}</td>
              <td><code>{{ item.url }}</code></td>
              <td class="text-center">
                <v-chip
                  size="small"
                  :color="item.is_default ? 'primary' : 'default'"
                  :variant="item.is_default ? 'flat' : 'outlined'"
                  class="cursor-pointer"
                  title="Нажмите для переключения"
                  @click="toggleFlag(item, 'is_default')"
                >
                  {{ item.is_default ? 'DEFAULT' : 'ДОП.' }}
                </v-chip>
              </td>
              <td class="text-center">
                <v-chip
                  size="small"
                  :color="item.is_active ? 'success' : 'default'"
                  class="cursor-pointer"
                  title="Нажмите для переключения"
                  @click="toggleFlag(item, 'is_active')"
                >
                  {{ item.is_active ? 'ON' : 'OFF' }}
                </v-chip>
              </td>
              <td class="text-center">
                <div class="d-flex justify-center ga-1">
                  <v-btn
                    icon="mdi-pencil"
                    size="x-small"
                    variant="text"
                    title="Редактировать"
                    @click="startEdit(item)"
                  />
                  <v-btn
                    icon="mdi-delete"
                    size="x-small"
                    variant="text"
                    color="error"
                    title="Удалить"
                    @click="remove(item)"
                  />
                </div>
              </td>
            </tr>
          </tbody>
        </v-table>
      </v-card-text>

      <v-card-actions class="px-6 pb-4">
        <v-spacer />
        <v-btn variant="text" @click="show = false">Закрыть</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.cursor-pointer {
  cursor: pointer;
}
</style>
