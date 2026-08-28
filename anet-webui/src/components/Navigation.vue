<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'

defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  logout: []
}>()

const router = useRouter()

const navigation = [
  { label: 'Overview', path: '/overview', icon: 'mdi-view-dashboard-outline', group: 'Overview' },
  { label: 'Users', path: '/users', icon: 'mdi-account-multiple-outline', group: 'Management' },
  { label: 'Nodes', path: '/servers', icon: 'mdi-server', group: 'Management' },
  { label: 'Node Pools', path: '/pools', icon: 'mdi-lan', group: 'Management' },
  { label: 'Route Maps', path: '/route-maps', icon: 'mdi-map-marker-path', group: 'Management' },
  { label: 'User Groups', path: '/groups', icon: 'mdi-wallet-membership', group: 'Management' },
  { label: 'Traffic', path: '/statistics', icon: 'mdi-chart-line', group: 'Observability' },
]
const groups = computed(() => [...new Set(navigation.map(item => item.group))])
</script>

<template>
  <v-navigation-drawer :model-value="modelValue" @update:model-value="emit('update:modelValue', $event)">
    <v-list-item title="ANet" subtitle="Control Plane" link @click="router.push('/overview')">
      <template #prepend>
        <v-avatar color="primary" size="34">A</v-avatar>
      </template>
    </v-list-item>

    <v-divider />

    <v-list nav density="comfortable" color="primary">
      <template v-for="group in groups" :key="group">
        <v-list-subheader>{{ group }}</v-list-subheader>
        <v-list-item
            v-for="item in navigation.filter(entry => entry.group === group)"
            :key="item.path"
            :to="item.path"
            :prepend-icon="item.icon"
            :title="item.label"
        />
      </template>
    </v-list>

    <template #append>
      <v-divider />
      <div class="pa-3">
        <div class="d-flex align-center ga-2 mb-3">
          <v-icon icon="mdi-circle-medium" color="success" size="18" />
          <div class="text-caption">
            <div class="font-weight-medium">Control plane</div>
            <div class="text-medium-emphasis">connected</div>
          </div>
        </div>
        <v-btn block variant="tonal" color="error" prepend-icon="mdi-logout" @click="emit('logout')">
          Sign out
        </v-btn>
      </div>
    </template>
  </v-navigation-drawer>
</template>
