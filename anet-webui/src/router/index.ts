import { createRouter, createWebHistory } from 'vue-router'

import Auth from '@/ui/Auth.vue'

const Users = () => import('@/ui/Users.vue')
const Servers = () => import('@/ui/Servers.vue')
const Statistics = () => import('@/ui/Statistics.vue')
const Pools = () => import('@/ui/Pools.vue')
const RouteMaps = () => import('@/ui/RouteMaps.vue')
const Overview = () => import('@/ui/Overview.vue')

const Groups = () => import('@/ui/Groups.vue')

const GroupDetail = () => import('@/ui/GroupDetail.vue')

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      component: Auth,
      meta: { isAuth: true },
    },
    { path: '/overview', component: Overview, meta: { title: 'Overview' } },
    { path: '/users', component: Users, meta: { title: 'Users' } },
    { path: '/servers', component: Servers, meta: { title: 'Nodes' } },
    { path: '/statistics', component: Statistics, meta: { title: 'Traffic' } },
    { path: '/pools', component: Pools, meta: { title: 'Node Pools' } },
    { path: '/route-maps', component: RouteMaps, meta: { title: 'Route Maps' } },
    { path: '/groups', component: Groups, meta: { title: 'User Groups' } },
    { path: '/groups/:id', component: GroupDetail, meta: { title: 'Параметры группы' } }
  ],
})

router.beforeEach((to) => {
  const token = localStorage.getItem('token')

  if (!to.meta.isAuth && !token) {
    return '/'
  }
  if (to.meta.isAuth && token) return '/overview'
})

export default router
