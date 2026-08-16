export type AppMessageKind = 'success' | 'error' | 'info' | 'warning'

export function useAppMessage() {
  const notify = (kind: AppMessageKind, message: string) => {
    window.dispatchEvent(new CustomEvent('anet:message', { detail: { kind, message } }))
  }

  return {
    success: (message: string) => notify('success', message),
    error: (message: string) => notify('error', message),
    info: (message: string) => notify('info', message),
    warning: (message: string) => notify('warning', message),
  }
}
