import { useEffect, useRef, useState } from 'react'
import { api } from './api'

export default function DocumentPreview({ attachment, onClose }) {
  const [preview, setPreview] = useState(null)
  const [error, setError] = useState(null)
  const dialogRef = useRef(null)
  const closeRef = useRef(null)

  useEffect(() => {
    let canceled = false
    api.previewAttachment(attachment.id)
      .then((data) => { if (!canceled) setPreview(data) })
      .catch((requestError) => { if (!canceled) setError(requestError.message) })
    return () => { canceled = true }
  }, [attachment.id])

  useEffect(() => {
    closeRef.current?.focus()
    function handleKeys(event) {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }
      if (event.key !== 'Tab') return
      const focusable = [...dialogRef.current.querySelectorAll('button:not(:disabled)')]
        .filter((element) => element.getClientRects().length > 0)
      const first = focusable[0]
      const last = focusable.at(-1)
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last?.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first?.focus()
      }
    }
    document.addEventListener('keydown', handleKeys)
    return () => document.removeEventListener('keydown', handleKeys)
  }, [onClose])

  return (
    <div className="document-preview-backdrop" onMouseDown={(event) => {
      if (event.target === event.currentTarget) onClose()
    }}>
      <section
        ref={dialogRef}
        className="document-preview"
        role="dialog"
        aria-modal="true"
        aria-labelledby="document-preview-title"
      >
        <header>
          <div>
            <h2 id="document-preview-title">Extracted text preview</h2>
            <p title={attachment.original_name}>{attachment.original_name}</p>
          </div>
          <button ref={closeRef} type="button" className="icon" onClick={onClose} aria-label="Close document preview">×</button>
        </header>
        <div className="document-preview-body">
          {!preview && !error && <div className="empty-list">Loading extracted text…</div>}
          {error && <div className="error-banner" role="alert">{error}</div>}
          {preview && (
            <>
              <div className="document-preview-meta">
                {preview.characters.toLocaleString()} extracted characters
                {preview.truncated && ' · preview truncated'}
              </div>
              <pre>{preview.text}</pre>
            </>
          )}
        </div>
        <footer>
          <span>Preview is loaded privately and is not cached.</span>
          <button type="button" onClick={onClose}>Done</button>
        </footer>
      </section>
    </div>
  )
}
