import { useEffect, useMemo, useRef, useState } from 'react'

function searchableText(action) {
  return [action.label, action.description, ...(action.keywords || [])]
    .filter(Boolean)
    .join(' ')
    .toLocaleLowerCase()
}

export default function CommandPalette({ actions, onClose }) {
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const dialogRef = useRef(null)
  const searchRef = useRef(null)
  const returnFocusRef = useRef(null)

  const visibleActions = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase()
    return normalized
      ? actions.filter((action) => searchableText(action).includes(normalized))
      : actions
  }, [actions, query])

  useEffect(() => {
    returnFocusRef.current = document.activeElement
    requestAnimationFrame(() => searchRef.current?.focus())
  }, [])

  function closeAndRestoreFocus() {
    const target = returnFocusRef.current
    onClose()
    requestAnimationFrame(() => {
      if (target?.isConnected && typeof target.focus === 'function') target.focus()
    })
  }

  function runAction(action) {
    if (!action || action.disabled) return
    onClose()
    action.onRun()
    if (action.restoreFocus !== false) {
      const target = returnFocusRef.current
      requestAnimationFrame(() => {
        if (target?.isConnected && typeof target.focus === 'function') target.focus()
      })
    }
  }

  function handleKeyDown(event) {
    if (event.key === 'Escape') {
      event.preventDefault()
      closeAndRestoreFocus()
      return
    }
    if (event.key === 'ArrowDown' && visibleActions.length) {
      event.preventDefault()
      setActiveIndex((index) => (index + 1) % visibleActions.length)
      return
    }
    if (event.key === 'ArrowUp' && visibleActions.length) {
      event.preventDefault()
      setActiveIndex((index) => (index - 1 + visibleActions.length) % visibleActions.length)
      return
    }
    if (event.key === 'Enter' && event.target !== dialogRef.current?.querySelector('[aria-label="Close commands"]')) {
      event.preventDefault()
      runAction(visibleActions[activeIndex])
      return
    }
    if (event.key !== 'Tab') return
    const focusable = [...dialogRef.current.querySelectorAll('button:not(:disabled), input:not(:disabled)')]
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

  return (
    <div className="command-palette-backdrop" onMouseDown={(event) => {
      if (event.target === event.currentTarget) closeAndRestoreFocus()
    }}>
      <section
        ref={dialogRef}
        className="command-palette"
        role="dialog"
        aria-modal="true"
        aria-labelledby="command-palette-title"
        onKeyDown={handleKeyDown}
      >
        <header>
          <div>
            <h2 id="command-palette-title">Quick actions</h2>
            <p>Navigate without leaving the keyboard.</p>
          </div>
          <button type="button" className="icon" aria-label="Close commands" onClick={closeAndRestoreFocus}>×</button>
        </header>
        <label className="command-search">
          <span aria-hidden="true">⌕</span>
          <span className="sr-only">Search commands</span>
          <input
            ref={searchRef}
            role="combobox"
            aria-controls="command-results"
            aria-expanded="true"
            aria-autocomplete="list"
            aria-activedescendant={visibleActions[activeIndex]
              ? `command-${visibleActions[activeIndex].id}`
              : undefined}
            type="search"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value.slice(0, 100))
              setActiveIndex(0)
            }}
            placeholder="Search actions…"
            autoComplete="off"
          />
        </label>
        <div id="command-results" className="command-results" role="listbox" aria-label="Commands">
          {visibleActions.length === 0 && (
            <p className="command-empty" role="status">No actions match “{query.trim()}”.</p>
          )}
          {visibleActions.map((action, index) => (
            <div
              id={`command-${action.id}`}
              key={action.id}
              className={`command-option ${index === activeIndex ? 'active' : ''} ${action.disabled ? 'disabled' : ''}`}
              role="option"
              aria-selected={index === activeIndex}
              aria-disabled={action.disabled || undefined}
              onMouseMove={() => setActiveIndex(index)}
              onMouseDown={(event) => event.preventDefault()}
              onClick={() => runAction(action)}
            >
              <span className="command-icon" aria-hidden="true">{action.icon}</span>
              <span className="command-copy">
                <strong>{action.label}</strong>
                <small>{action.disabled ? (action.disabledReason || 'Unavailable now') : action.description}</small>
              </span>
              {action.hint && <kbd>{action.hint}</kbd>}
            </div>
          ))}
        </div>
        <footer>
          <span><kbd>↑↓</kbd> navigate</span>
          <span><kbd>↵</kbd> choose</span>
          <span><kbd>Esc</kbd> close</span>
        </footer>
      </section>
    </div>
  )
}
