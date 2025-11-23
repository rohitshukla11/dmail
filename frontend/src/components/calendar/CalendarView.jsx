import { useState, useMemo } from 'react'
import PropTypes from 'prop-types'

function CalendarView({ events, onAddEvent, onEventClick, loading }) {
  const [currentDate, setCurrentDate] = useState(new Date())

  // Get calendar grid data
  const { year, month, daysInMonth, firstDayOfMonth, prevMonthDays, nextMonthStart } = useMemo(() => {
    const year = currentDate.getFullYear()
    const month = currentDate.getMonth()
    const firstDay = new Date(year, month, 1)
    const lastDay = new Date(year, month + 1, 0)
    const daysInMonth = lastDay.getDate()
    const firstDayOfMonth = firstDay.getDay() // 0 = Sunday
    
    // Calculate days from previous month to show
    const prevMonth = new Date(year, month, 0)
    const prevMonthDays = prevMonth.getDate()
    
    // Calculate when next month starts in the grid
    const totalCells = Math.ceil((daysInMonth + firstDayOfMonth) / 7) * 7
    const nextMonthStart = totalCells - (daysInMonth + firstDayOfMonth)
    
    return { year, month, daysInMonth, firstDayOfMonth, prevMonthDays, nextMonthStart }
  }, [currentDate])

  // Group events by date
  const eventsByDate = useMemo(() => {
    const grouped = {}
    events.forEach((event) => {
      if (!event.startTime) return
      const eventDate = new Date(event.startTime)
      const dateKey = `${eventDate.getFullYear()}-${eventDate.getMonth()}-${eventDate.getDate()}`
      if (!grouped[dateKey]) {
        grouped[dateKey] = []
      }
      grouped[dateKey].push(event)
    })
    // Sort events by start time within each date
    Object.keys(grouped).forEach((key) => {
      grouped[key].sort((a, b) => new Date(a.startTime) - new Date(b.startTime))
    })
    return grouped
  }, [events])

  const goToPreviousMonth = () => {
    setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() - 1, 1))
  }

  const goToNextMonth = () => {
    setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 1))
  }

  const goToToday = () => {
    setCurrentDate(new Date())
  }

  const monthNames = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'
  ]

  const weekDays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

  // Generate calendar cells
  const calendarCells = []
  
  // Previous month days
  for (let i = firstDayOfMonth - 1; i >= 0; i--) {
    const day = prevMonthDays - i
    const cellMonth = month === 0 ? 11 : month - 1
    const cellYear = month === 0 ? year - 1 : year
    calendarCells.push({
      day,
      month: cellMonth,
      year: cellYear,
      isCurrentMonth: false,
      isToday: false,
      dateKey: `${cellYear}-${cellMonth}-${day}`,
    })
  }
  
  // Current month days
  const today = new Date()
  for (let day = 1; day <= daysInMonth; day++) {
    const isToday =
      today.getDate() === day &&
      today.getMonth() === month &&
      today.getFullYear() === year
    calendarCells.push({
      day,
      month,
      year,
      isCurrentMonth: true,
      isToday,
      dateKey: `${year}-${month}-${day}`,
    })
  }
  
  // Next month days
  const remainingCells = calendarCells.length % 7
  const nextMonthDays = remainingCells === 0 ? 0 : 7 - remainingCells
  for (let day = 1; day <= nextMonthDays; day++) {
    const cellMonth = month === 11 ? 0 : month + 1
    const cellYear = month === 11 ? year + 1 : year
    calendarCells.push({
      day,
      month: cellMonth,
      year: cellYear,
      isCurrentMonth: false,
      isToday: false,
      dateKey: `${cellYear}-${cellMonth}-${day}`,
    })
  }

  const formatEventTime = (event) => {
    const start = new Date(event.startTime)
    const end = event.endTime ? new Date(event.endTime) : null
    const timeStr = start.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })
    if (end && start.toDateString() === end.toDateString()) {
      return `${timeStr} - ${end.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })}`
    }
    return timeStr
  }

  return (
    <div className="calendar-view-container">
      <div className="calendar-view-header">
        <div className="calendar-view-title">
          <h2>{monthNames[month]} {year}</h2>
        </div>
        <div className="calendar-view-controls">
          <button className="calendar-nav-btn" onClick={goToPreviousMonth} aria-label="Previous month">
            ‹
          </button>
          <button className="calendar-today-btn" onClick={goToToday}>
            Today
          </button>
          <button className="calendar-nav-btn" onClick={goToNextMonth} aria-label="Next month">
            ›
          </button>
          <button className="calendar-add-event-btn" onClick={onAddEvent}>
            + Create Event
          </button>
        </div>
      </div>

      {loading && (
        <div className="calendar-loading-overlay">
          <span>⏳ Loading events...</span>
        </div>
      )}

      <div className="calendar-grid-container">
        <div className="calendar-weekdays">
          {weekDays.map((day) => (
            <div key={day} className="calendar-weekday">
              {day}
            </div>
          ))}
        </div>

        <div className="calendar-grid">
          {calendarCells.map((cell, index) => {
            const cellEvents = eventsByDate[cell.dateKey] || []
            const hasEvents = cellEvents.length > 0
            
            return (
              <div
                key={`${cell.dateKey}-${index}`}
                className={`calendar-day-cell ${
                  cell.isCurrentMonth ? '' : 'other-month'
                } ${cell.isToday ? 'today' : ''} ${hasEvents ? 'has-events' : ''}`}
              >
                <div className="calendar-day-number">{cell.day}</div>
                <div className="calendar-day-events">
                  {cellEvents.slice(0, 3).map((event) => (
                    <div
                      key={event.id}
                      className="calendar-event-item"
                      onClick={() => onEventClick && onEventClick(event)}
                      title={`${event.title}\n${formatEventTime(event)}${event.location ? `\n${event.location}` : ''}`}
                    >
                      <span className="event-time">{formatEventTime(event)}</span>
                      <span className="event-title">{event.title}</span>
                    </div>
                  ))}
                  {cellEvents.length > 3 && (
                    <div className="calendar-more-events">
                      +{cellEvents.length - 3} more
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

CalendarView.propTypes = {
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
  onAddEvent: PropTypes.func.isRequired,
  onEventClick: PropTypes.func,
  loading: PropTypes.bool,
}

CalendarView.defaultProps = {
  events: [],
  loading: false,
  onEventClick: null,
}

export default CalendarView

