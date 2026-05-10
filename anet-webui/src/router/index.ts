// src/router/index.ts
import { createRouter, createWebHistory } from 'vue-router'

import Auth from '@/ui/Auth.vue'
import Users from '@/ui/Users.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      component: Auth,
      meta: { isAuth: true },
    },
    { path: '/users', component: Users },
  ],
})

router.beforeEach((to) => {
  const token = localStorage.getItem('token')

  if (!to.meta.isAuth && !token) {
    return '/'
  }
})

export default router
