<script setup lang="ts">
import { watch } from 'vue'

import UserForm from './UserForm.vue'
import RateEditForm from './RateEditForm.vue'
import RateCreateForm from './RateCreateForm.vue'

import { useUser } from '@/composables/useUser'
import { useRate } from '@/composables/useRate'

const show = defineModel<boolean>('show')

const props = defineProps<{
  userId: string | null
}>()

const emit = defineEmits<{
  (e: 'updated'): void
  (e: 'close'): void
}>()

const { user, loading, regenerating, loadUser, saveUser, regenerate } = useUser()

const { saving, saveRate, createRate } = useRate(user)

watch(
  () => props.userId,
  (id) => {
    if (id) loadUser(id)
  },
  { immediate: true },
)
const close = () => {
  show.value = false
  user.value = null

  emit('close')
}
</script>

<template>
  <n-modal
    v-model:show="show"
    @update:show="close()"
    preset="card"
    style="width: min(900px, calc(100vw - 48px)); max-height: calc(100vh - 120px); overflow-y: auto"
  >
    <n-card>
      <UserForm v-if="user" v-model="user" />

      <n-button type="primary" @click="saveUser"> Save User </n-button>

      <RateEditForm v-if="user?.rate" v-model="user" @save="saveRate" />

      <RateCreateForm v-else @create="createRate" />

      <n-divider />

      <n-button type="warning" :loading="regenerating" @click="regenerate"> Regenerate </n-button>
      <n-button @click="close"> Close </n-button>
    </n-card>
  </n-modal>
</template>
