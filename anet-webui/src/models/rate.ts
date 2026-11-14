export type RateReqRequest = {
  sessions: number
  date_end: string
  traffic_limit?: number
  speed_limit?: number
}

export type UpdateRateRequest = {
  sessions?: number
  date_end?: string
  traffic_limit?: number
  speed_limit?: number
}

export type Rate = {
  id: string
  sessions: number
  date_end: string
  traffic_limit: number
  speed_limit: number
}
