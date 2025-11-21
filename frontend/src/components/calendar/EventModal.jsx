import { useState } from 'react'
import PropTypes from 'prop-types'

const initialState = {
  title: '',
  description: '',
  location: '',
  startTime: '',
  endTime: '',
  attendees: '',
}

export default function EventModal({ onClose, onSave, saving }) {
  const [form, setForm] = useState(initialState)
  const [error, setError] = useState('')

  const handleClose = () => {
    setForm(initialState)
    setError('')
    onClose()
  }

  const handleChange = (event) => {
    const { name, value } = event.target
    setForm((prev) => ({
      ...prev,
      [name]: value,
    }))
  }

  const handleSubmit = (event) => {
    event?.preventDefault()
    setError('')

    if (!form.title.trim()) {
      setError('Event title is required')
      return
    }
    if (!form.startTime || !form.endTime) {
      setError('Please provide start and end times')
      return
    }

    const start = new Date(form.startTime)
    const end = new Date(form.endTime)
    if (end <= start) {
      setError('End time must be after start time')
      return
    }

    const attendees = form.attendees
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean)

    onSave({
      title: form.title,
      description: form.description,
      location: form.location,
      startTime: start.toISOString(),
      endTime: end.toISOString(),
      attendees,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    })
  }

  return (
    <div className="compose-modal-overlay">
      <div className="compose-modal calendar-modal">
        <div className="compose-header">
          <h3>Create Event</h3>
          <button className="close-btn" onClick={handleClose} aria-label="Close">
            ✕
          </button>
        </div>

        <form className="compose-form" onSubmit={handleSubmit}>
          <div className="compose-field">
            <input
              type="text"
              name="title"
              placeholder="Event title"
              value={form.title}
              onChange={handleChange}
              required
            />
          </div>

          <div className="compose-field">
            <input
              type="text"
              name="location"
              placeholder="Location"
              value={form.location}
              onChange={handleChange}
            />
          </div>

          <div className="calendar-time-fields">
            <label>
              Start
              <input type="datetime-local" name="startTime" value={form.startTime} onChange={handleChange} required />
            </label>
            <label>
              End
              <input type="datetime-local" name="endTime" value={form.endTime} onChange={handleChange} required />
            </label>
          </div>

          <div className="compose-field">
            <input
              type="text"
              name="attendees"
              placeholder="Attendees (comma separated ENS or emails)"
              value={form.attendees}
              onChange={handleChange}
            />
          </div>

          <div className="compose-body calendar-description">
            <textarea
              name="description"
              placeholder="Add description"
              value={form.description}
              onChange={handleChange}
            />
          </div>

          {error ? <div className="field-status error">{error}</div> : null}

          <div className="compose-footer">
            <button className="send-btn" type="submit" disabled={saving}>
              {saving ? 'Saving…' : 'Save Event'}
            </button>
            <button className="attach-btn" type="button" onClick={handleClose}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

EventModal.propTypes = {
  onClose: PropTypes.func.isRequired,
  onSave: PropTypes.func.isRequired,
  saving: PropTypes.bool,
}

EventModal.defaultProps = {
  saving: false,
}

