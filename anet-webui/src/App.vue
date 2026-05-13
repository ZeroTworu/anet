<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()

const logout = () => {
  localStorage.removeItem('token')
  router.push('/')
}
</script>

<template>
  <div>
    <!-- HEADER только если НЕ login -->
    <n-layout-header v-if="!route.meta.isAuth" bordered>
      <div style="display: flex; justify-content: end; padding: 10px">
        <n-button type="error" @click="logout"> Logout </n-button>
      </div>
    </n-layout-header>

    <router-view />
  </div>
</template>
