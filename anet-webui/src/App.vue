<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useDisplay } from 'vuetify'
import Navigation from '@/components/Navigation.vue'

const route = useRoute()
const router = useRouter()
const { mobile } = useDisplay()

const drawer = ref(!mobile.value)
const snackbar = ref({ open: false, message: '', color: 'info' })
const pageTitle = computed(() => String(route.meta.title || 'ANet'))

// На мобильном drawer — оверлей поверх контента, поэтому закрываем его после
// перехода; на десктопе он постоянно закреплён и закрывать его не нужно.
watch(() => route.path, () => {
  if (mobile.value) drawer.value = false
})

const onMessage = (event: Event) => {
  const detail = (event as CustomEvent<{ kind: string; message: string }>).detail
  snackbar.value = { open: true, message: detail.message, color: detail.kind }
}

onMounted(() => window.addEventListener('anet:message', onMessage))
onBeforeUnmount(() => window.removeEventListener('anet:message', onMessage))

const logout = () => {
  localStorage.removeItem('token')
  router.push('/')
}
</script>

<template>
  <v-app>
    <router-view v-if="route.meta.isAuth" />

    <template v-else>
      <Navigation v-model="drawer" @logout="logout" />

      <v-app-bar flat border>
        <v-app-bar-nav-icon @click="drawer = !drawer" />
        <v-toolbar-title>{{ pageTitle }}</v-toolbar-title>
        <v-spacer />
        <v-chip size="small" variant="tonal" color="success" prepend-icon="mdi-circle-medium">
          Live
        </v-chip>
      </v-app-bar>

      <v-main>
        <v-container fluid>
          <router-view />
        </v-container>
      </v-main>
    </template>

    <v-snackbar v-model="snackbar.open" :color="snackbar.color" :timeout="4000">
      {{ snackbar.message }}
    </v-snackbar>
  </v-app>
</template>
