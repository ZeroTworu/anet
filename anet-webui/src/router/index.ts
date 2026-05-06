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
        meta: {isAuth: true}
    },
    { path: '/users', component: Users },
  ],
})

export default router
