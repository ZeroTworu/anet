export function toQuery(params: Record<string, string | number | null | undefined>) {
  const search = new URLSearchParams()

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      search.append(key, String(value))
    }
  })

  return search.toString()
}

export function formatDate(date: Date, format: string): string {
  const pad = (num: number, len = 2) => String(num).padStart(len, '0')

  const map: Record<string, string> = {
    YYYY: String(date.getFullYear()),
    yyyy: String(date.getFullYear()),

    YY: String(date.getFullYear()).slice(-2),
    yy: String(date.getFullYear()).slice(-2),

    MM: pad(date.getMonth() + 1),
    M: String(date.getMonth() + 1),

    DD: pad(date.getDate()),
    dd: pad(date.getDate()),
    D: String(date.getDate()),
    d: String(date.getDate()),

    HH: pad(date.getHours()),
    H: String(date.getHours()),

    mm: pad(date.getMinutes()),
    m: String(date.getMinutes()),

    ss: pad(date.getSeconds()),
    s: String(date.getSeconds()),

    SSS: pad(date.getMilliseconds(), 3),
  }
  return format.replace(
    /YYYY|yyyy|YY|yy|MM|M|DD|dd|D|d|HH|H|mm|m|ss|s|SSS/g,
    (token) => map[token] ?? token,
  )
}
