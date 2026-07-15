<script setup lang="ts">
import { ref, watch } from 'vue'
import { UpdateServer } from '@/api/servers'
import type { Server } from '@/models/server'

const show = defineModel<boolean>('show')

const props = defineProps<{
  server: Server | null
}>()

const emit = defineEmits<{
  (e: 'updated'): void
  (e: 'close'): void
}>()

const form = ref({
  name: '',
  address: '',
  public_key: '',
  quic_port: null as number | null,
  ssh_port: null as number | null,
  vnc_port: null as number | null,
  ssh_user: '',
  is_active: true
})

const loading = ref(false)

watch(
    () => props.server,
    (val) => {
      if (val) {
        form.value = {
          name: val.name,
          address: val.address,
          public_key: val.public_key,
          quic_port: val.quic_port,
          ssh_port: val.ssh_port,
          vnc_port: val.vnc_port,
          ssh_user: val.ssh_user || '',
          is_active: val.is_active
        }
      }
    },
    { immediate: true }
)

const save = async () => {
  if (!props.server) return
  loading.value = true
  try {
    await UpdateServer(props.server.id, form.value)
    emit('updated')
    show.value = false
  } catch (e) {
    console.error(e)
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
  <n-modal v-model:show="show" @update:show="close" preset="card" style="width: 650px;" title="Редактировать физический сервер">
    <n-form>
      <n-form-item label="Название локации">
        <n-input v-model:value="form.name" />
      </n-form-item>

      <n-form-item label="IP Адрес или Домен">
        <n-input v-model:value="form.address" />
      </n-form-item>

      <n-form-item label="Публичный ключ сервера">
        <n-input v-model:value="form.public_key" />
      </n-form-item>

      <n-space item-style="width: 175px;">
        <n-form-item label="QUIC Port (UDP)">
          <n-input-number v-model:value="form.quic_port" clearable />
        </n-form-item>

        <n-form-item label="SSH Port (TCP)">
          <n-input-number v-model:value="form.ssh_port" clearable />
        </n-form-item>

        <n-form-item label="VNC Port (TCP)">
          <n-input-number v-model:value="form.vnc_port" clearable />
        </n-form-item>
      </n-space>

      <n-form-item label="Пользователь SSH">
        <n-input v-model:value="form.ssh_user" />
      </n-form-item>

      <n-form-item label="Статус (ВКЛ / ВЫКЛ)">
        <n-switch v-model:value="form.is_active" />
      </n-form-item>
    </n-form>
    <template #footer>
      <n-space justify="end">
        <n-button @click="close">Cancel</n-button>
        <n-button type="primary" :loading="loading" @click="save"> Save </n-button>
      </n-space>
    </template>
  </n-modal>
</template>
