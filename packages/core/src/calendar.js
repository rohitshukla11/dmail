import { synapseFetch, synapseUpload, normalizeServiceUrl, getStorageServiceUrl } from './synapse.js'

const CALENDAR_VERSION = 1

function ensureArray(value) {
  if (!value) return []
  return Array.isArray(value) ? value : [value]
}

function generateEventId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return `event-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function normalizeIsoDate(value) {
  if (!value) return new Date().toISOString()
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return new Date().toISOString()
  }
  return date.toISOString()
}

export function createEmptyCalendar(ownerEns) {
  return {
    owner: ownerEns ?? null,
    version: CALENDAR_VERSION,
    updatedAt: new Date().toISOString(),
    events: [],
  }
}

export function appendCalendarEvent(calendar, eventInput = {}) {
  if (!calendar) {
    throw new Error('appendCalendarEvent: calendar is required')
  }

  const event = {
    id: generateEventId(),
    title: eventInput.title?.trim() || 'Untitled Event',
    description: eventInput.description?.trim() || '',
    location: eventInput.location?.trim() || '',
    startTime: normalizeIsoDate(eventInput.startTime),
    endTime: normalizeIsoDate(eventInput.endTime),
    attendees: ensureArray(eventInput.attendees)
      .map((attendee) => attendee.trim())
      .filter(Boolean),
    timezone: eventInput.timezone ?? Intl.DateTimeFormat?.().resolvedOptions().timeZone ?? 'UTC',
    shared: Boolean(eventInput.shared ?? eventInput.attendees?.length > 0),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    metadata: eventInput.metadata ?? {},
  }

  const events = Array.isArray(calendar.events) ? [...calendar.events, event] : [event]

  return {
    ...calendar,
    updatedAt: new Date().toISOString(),
    events,
  }
}

export async function loadCalendarFromCid(calendarUploadResult, options = {}) {
  if (!calendarUploadResult || !calendarUploadResult.cid) {
    if (options.optional) return null
    throw new Error('loadCalendarFromCid: calendar upload result with cid is required')
  }

  if (!calendarUploadResult.pieceCid) {
    if (options.optional) return null
    throw new Error('loadCalendarFromCid: calendar upload result must include pieceCid for Synapse retrieval')
  }

  let providerInfo = calendarUploadResult.providerInfo
  if (!providerInfo && calendarUploadResult.serviceURL) {
    const baseInfo = {
      id: calendarUploadResult.providerId,
      address: calendarUploadResult.providerAddress,
      products: {},
    }
    const productKey = 'STORAGE'
    baseInfo.products[productKey] = {
      data: {
        serviceURL: normalizeServiceUrl(calendarUploadResult.serviceURL),
      },
    }
    providerInfo = baseInfo
  }

  if (!providerInfo) {
    if (options.optional) return null
    throw new Error('loadCalendarFromCid: providerInfo (or serviceURL) is required for Synapse retrieval')
  }

  // Normalize provider info URLs (old entries may have outdated URL formats)
  const serviceUrl = getStorageServiceUrl(providerInfo)
  if (serviceUrl) {
    const normalizedUrl = normalizeServiceUrl(serviceUrl)
    const productKey = 'STORAGE'
    providerInfo = {
      ...providerInfo,
      products: {
        ...providerInfo.products,
        [productKey]: {
          ...providerInfo.products?.[productKey],
          data: {
            ...providerInfo.products?.[productKey]?.data,
            serviceURL: normalizedUrl,
          },
        },
      },
    }
  }

  const calendar = await synapseFetch(calendarUploadResult.cid, {
    as: 'json',
    pieceCid: calendarUploadResult.pieceCid,
    providerInfo,
    ...options,
  })

  if (!calendar || typeof calendar !== 'object') {
    throw new Error('Calendar payload is not a valid object')
  }

  if (!Array.isArray(calendar.events)) {
    calendar.events = []
  }

  return calendar
}

export async function persistCalendar(calendar, options = {}) {
  if (!calendar) {
    throw new Error('persistCalendar: calendar is required')
  }

  const payload = JSON.stringify(calendar, null, 2)
  return await synapseUpload(payload, {
    filename: options.filename ?? 'calendar.json',
    metadata: {
      type: 'dmail-calendar',
      owner: calendar.owner ?? options.owner ?? 'unknown',
    },
    ...options.uploadOptions,
  })
}

function formatDateTimeForIcs(date) {
  const iso = normalizeIsoDate(date).replace(/[-:]/g, '')
  return iso.split('.')[0] + 'Z'
}

export function generateCalendarIcs(event, organizerEns) {
  if (!event) {
    throw new Error('generateCalendarIcs: event is required')
  }

  const uid = event.id ?? generateEventId()
  const dtStamp = formatDateTimeForIcs(new Date().toISOString())
  const dtStart = formatDateTimeForIcs(event.startTime)
  const dtEnd = formatDateTimeForIcs(event.endTime)
  const organizer = organizerEns ? `ORGANIZER;CN=${organizerEns}:mailto:${organizerEns}` : ''
  const attendees = ensureArray(event.attendees)
    .map((attendee) => attendee && `ATTENDEE;CN=${attendee}:mailto:${attendee}`)
    .filter(Boolean)
    .join('\n')

  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//dMail Calendar//EN',
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    'BEGIN:VEVENT',
    `UID:${uid}`,
    `DTSTAMP:${dtStamp}`,
    `DTSTART:${dtStart}`,
    `DTEND:${dtEnd}`,
    organizer,
    attendees,
    `SUMMARY:${event.title ?? 'Untitled Event'}`,
    `DESCRIPTION:${event.description ?? ''}`,
    `LOCATION:${event.location ?? ''}`,
    'END:VEVENT',
    'END:VCALENDAR',
  ].filter(Boolean)

  return lines.join('\n')
}

