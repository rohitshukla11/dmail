import PropTypes from 'prop-types'

function formatEventTime(event) {
  if (!event?.startTime) return 'No start time'
  const start = new Date(event.startTime)
  const end = event.endTime ? new Date(event.endTime) : null
  const options = { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }
  const startLabel = start.toLocaleString(undefined, options)
  if (!end) return startLabel
  if (start.toDateString() === end.toDateString()) {
    return `${startLabel} - ${end.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })}`
  }
  return `${startLabel} → ${end.toLocaleString(undefined, options)}`
}

export default function CalendarSidebar({
  events,
  loading,
  error,
  onRefresh,
  onAddEvent,
  onShareEvent,
  fullPage,
  onToggleFullPage,
}) {
  const sortedEvents = [...events]
    .sort((a, b) => new Date(a.startTime) - new Date(b.startTime))
    .slice(0, fullPage ? undefined : 10)

  return (
    <aside className={`calendar-sidebar ${fullPage ? 'full-page' : ''}`}>
      <div className="calendar-header">
        <p className="calendar-title">📅 Calendar</p>
        <div className="calendar-actions">
          <button className="calendar-icon-btn" onClick={onRefresh} aria-label="Refresh calendar" disabled={loading} title="Refresh">
            ↻
          </button>
          <button className="calendar-icon-btn" onClick={onToggleFullPage} aria-label={fullPage ? 'Minimize calendar' : 'Expand calendar'} title={fullPage ? 'Minimize' : 'Expand'}>
            {fullPage ? '⊟' : '⊞'}
          </button>
          <button className="calendar-add-btn" onClick={onAddEvent}>
            + Create
          </button>
        </div>
      </div>
      {error && <div className="calendar-error-bar">{error}</div>}
      <div className="calendar-body">
        {loading && sortedEvents.length === 0 ? (
          <div className="calendar-empty">
            <span role="img" aria-label="Loading">
              ⏳
            </span>
            <p>Loading events...</p>
          </div>
        ) : sortedEvents.length === 0 ? (
          <div className="calendar-empty">
            <span role="img" aria-label="Calendar">
              📅
            </span>
            <p>No upcoming events</p>
            <button onClick={onAddEvent}>Create your first event</button>
          </div>
        ) : (
          <ul className="calendar-event-list">
            {sortedEvents.map((event) => (
              <li key={event.id} className="calendar-event-card">
                <div className="calendar-event-info">
                  <p className="calendar-event-title">{event.title}</p>
                  <p className="calendar-event-time">{formatEventTime(event)}</p>
                  {event.location ? <p className="calendar-event-location">{event.location}</p> : null}
                  {event.attendees?.length ? (
                    <p className="calendar-event-attendees">
                      {event.attendees.length === 1
                        ? `1 attendee`
                        : `${event.attendees.length} attendees`}
                    </p>
                  ) : null}
                </div>
                <div className="calendar-event-actions">
                  <button className="calendar-icon-btn" onClick={() => onShareEvent(event)} title="Share event">
                    ↗
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </aside>
  )
}

CalendarSidebar.propTypes = {
  events: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string,
      title: PropTypes.string,
      startTime: PropTypes.string,
      endTime: PropTypes.string,
      location: PropTypes.string,
      attendees: PropTypes.arrayOf(PropTypes.string),
    })
  ),
  loading: PropTypes.bool,
  error: PropTypes.string,
  onRefresh: PropTypes.func.isRequired,
  onAddEvent: PropTypes.func.isRequired,
  onShareEvent: PropTypes.func.isRequired,
  fullPage: PropTypes.bool,
  onToggleFullPage: PropTypes.func.isRequired,
}

CalendarSidebar.defaultProps = {
  events: [],
  loading: false,
  error: '',
  fullPage: false,
}

