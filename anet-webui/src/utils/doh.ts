import { computed, ref } from 'vue'
import { GetDohResolvers } from '@/api/doh-resolvers'
import type { DohResolver } from '@/models/doh-resolver'

export interface DohConfigParams {
  domain: string
  resolvers: string[]
  arq: boolean
  dup_hs: boolean
  hold_ms: number
}

export const FALLBACK_DEFAULT_DOH_RESOLVERS = [
  'https://77.88.8.7/dns-query',
  'https://dns.adguard-dns.com/dns-query',
]

export const FALLBACK_PRESET_DOH_RESOLVERS = [
  'https://77.88.8.7/dns-query',
  'https://dns.adguard-dns.com/dns-query',
  'https://common.dot.dns.yandex.net/dns-query',
  'https://1.1.1.1/dns-query',
  'https://8.8.8.8/dns-query',
  'https://9.9.9.9/dns-query',
]

const dohResolversList = ref<DohResolver[]>([])
const dohResolversLoaded = ref(false)
const dohResolversLoading = ref(false)

export const presetDohResolvers = computed<string[]>(() => {
  const active = dohResolversList.value.filter(r => r.is_active).map(r => r.url)
  return active.length > 0 ? active : FALLBACK_PRESET_DOH_RESOLVERS
})

export const defaultDohResolvers = computed<string[]>(() => {
  const active = dohResolversList.value.filter(r => r.is_active)
  const defaults = active.filter(r => r.is_default).map(r => r.url)
  if (defaults.length > 0) return defaults
  if (active.length > 0) return active.map(r => r.url)
  return FALLBACK_DEFAULT_DOH_RESOLVERS
})

export async function loadDohResolvers(force = false): Promise<DohResolver[]> {
  if (dohResolversLoaded.value && !force) {
    return dohResolversList.value
  }
  if (dohResolversLoading.value) {
    return dohResolversList.value
  }
  dohResolversLoading.value = true
  try {
    dohResolversList.value = await GetDohResolvers()
    dohResolversLoaded.value = true
  } catch (err) {
    console.warn('Не удалось загрузить список DoH-резолверов из БД:', err)
  } finally {
    dohResolversLoading.value = false
  }
  return dohResolversList.value
}

export function useDohResolvers() {
  return {
    resolvers: dohResolversList,
    loading: dohResolversLoading,
    loaded: dohResolversLoaded,
    presetResolvers: presetDohResolvers,
    defaultResolvers: defaultDohResolvers,
    reloadResolvers: () => loadDohResolvers(true),
    ensureLoaded: () => loadDohResolvers(false),
  }
}

export function parseDohDsn(raw: string | null | undefined): DohConfigParams {
  const fallback = defaultDohResolvers.value
  const trimmed = (raw || '').trim()
  if (!trimmed) {
    return {
      domain: '',
      resolvers: [...fallback],
      arq: true,
      dup_hs: true,
      hold_ms: 1200,
    }
  }

  const withoutScheme = trimmed.replace(/^[a-zA-Z0-9+.-]+:\/\//, '')
  const qIndex = withoutScheme.indexOf('?')
  const hostPart = (qIndex >= 0 ? withoutScheme.slice(0, qIndex) : withoutScheme).replace(/\/+$/, '')
  const queryPart = qIndex >= 0 ? withoutScheme.slice(qIndex + 1) : ''

  const params = new URLSearchParams(queryPart)
  const resolvers = params.getAll('resolver').map(r => r.trim()).filter(Boolean)
  const arqParam = params.get('arq')
  const dupHsParam = params.get('dup_hs')
  const holdMsParam = params.get('hold_ms')

  return {
    domain: hostPart,
    resolvers: resolvers.length > 0 ? resolvers : [...fallback],
    arq: arqParam !== null ? arqParam !== 'false' && arqParam !== '0' : true,
    dup_hs: dupHsParam !== null ? dupHsParam !== 'false' && dupHsParam !== '0' : true,
    hold_ms: holdMsParam !== null && !Number.isNaN(Number(holdMsParam)) ? Number(holdMsParam) : 1200,
  }
}

export function buildDohDsn(cfg: DohConfigParams): string {
  const rawHost = cfg.domain.trim().replace(/^[a-zA-Z0-9+.-]+:\/\//, '').split('?')[0] ?? ''
  const domain = rawHost.replace(/\/+$/, '')
  if (!domain) {
    return ''
  }

  const queryParts: string[] = []
  const resolvers = cfg.resolvers.map(r => r.trim()).filter(Boolean)
  for (const r of resolvers) {
    queryParts.push(`resolver=${r}`)
  }
  queryParts.push(`arq=${cfg.arq ? 'true' : 'false'}`)
  queryParts.push(`dup_hs=${cfg.dup_hs ? 'true' : 'false'}`)
  queryParts.push(`hold_ms=${cfg.hold_ms > 0 ? cfg.hold_ms : 1200}`)

  return `doh://${domain}?${queryParts.join('&')}`
}
