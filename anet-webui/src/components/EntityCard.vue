<script setup lang="ts">
defineProps<{
  title: string
  subtitle?: string
}>()

defineEmits<{ click: [] }>()
</script>

<template>
  <v-card hover class="pa-4 h-100 cursor-pointer d-flex flex-column" @click="$emit('click')">
    <div class="d-flex justify-space-between align-start mb-3">
      <div>
        <div class="d-flex align-center ga-2 mb-1">
          <strong class="text-h6">{{ title }}</strong>
          <slot name="badges" />
        </div>
        <div v-if="subtitle" class="text-medium-emphasis text-body-2">{{ subtitle }}</div>
      </div>
      <div class="d-flex flex-column align-end ga-2">
        <slot name="meta" />
      </div>
    </div>

    <template v-if="$slots.footer">
      <v-spacer />
      <div class="d-flex flex-wrap ga-2 mt-auto pt-2 border-t">
        <slot name="footer" />
      </div>
    </template>
  </v-card>
</template>
