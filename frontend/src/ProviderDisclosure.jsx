import { useEffect, useRef } from 'react'

export default function ProviderDisclosure({ busy, error, onAccept, onClose }) {
  const dialogRef = useRef(null)
  const acceptRef = useRef(null)
  const closeRef = useRef(onClose)

  useEffect(() => {
    closeRef.current = onClose
  }, [onClose])

  useEffect(() => {
    acceptRef.current?.focus()
    function handleKeys(event) {
      if (event.key === 'Escape' && !busy) {
        event.preventDefault()
        closeRef.current()
        return
      }
      if (event.key !== 'Tab') return
      const focusable = [...dialogRef.current.querySelectorAll(
        'button:not(:disabled), a[href]',
      )].filter((element) => element.getClientRects().length > 0)
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
  }, [busy])

  return (
    <div className="document-preview-backdrop provider-disclosure-backdrop">
      <section
        ref={dialogRef}
        className="document-preview provider-disclosure"
        role="dialog"
        aria-modal="true"
        aria-busy={busy}
        aria-labelledby="provider-disclosure-title"
        aria-describedby="provider-disclosure-summary"
      >
        <header>
          <div>
            <h2 id="provider-disclosure-title">Before your first AI request</h2>
            <p>NVIDIA is an external model provider.</p>
          </div>
        </header>
        <div className="document-preview-body">
          <p id="provider-disclosure-summary">
            To generate a response, this app sends the following selected content to NVIDIA:
          </p>
          <ul>
            <li>Your prompt and the relevant conversation context.</li>
            <li>Only documents and images marked as included.</li>
            <li>For image generation, your prompt and generation settings.</li>
          </ul>
          <p>
            Do not continue with personal, confidential, or third-party data you are not allowed
            to share. This acknowledgement records only your user ID, its version, and the time;
            it does not copy your prompt or filenames.
          </p>
          <p className="provider-disclosure-links">
            Review NVIDIA's{' '}
            <a href="https://www.nvidia.com/en-us/about-nvidia/privacy-policy/" target="_blank" rel="noreferrer">
              privacy policy
            </a>{' '}and{' '}
            <a href="https://developer.nvidia.com/legal/terms" target="_blank" rel="noreferrer">
              applicable service terms
            </a>.
          </p>
          {error && <div className="error-banner" role="alert">{error}</div>}
        </div>
        <footer>
          <button type="button" onClick={onClose} disabled={busy}>Cancel</button>
          <button ref={acceptRef} type="button" className="primary" onClick={onAccept} disabled={busy}>
            {busy ? 'Recording…' : 'I understand — continue'}
          </button>
        </footer>
      </section>
    </div>
  )
}
