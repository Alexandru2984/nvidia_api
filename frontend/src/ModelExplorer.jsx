import { useEffect, useMemo, useRef, useState } from 'react'

const STORAGE_KEY = 'aichat-model-preferences-v1'
const MAX_STORED_BYTES = 8192
const MAX_FAVORITES = 24
const MAX_RECENT = 6
const MAX_COMPARE = 3
const PURPOSES = [
  ['all', 'All'],
  ['assistant', 'Assistants'],
  ['coding', 'Coding'],
  ['translation', 'Translation'],
  ['safety', 'Safety'],
  ['specialized', 'Specialized'],
]
const SORTS = [
  ['recommended', 'Recommended'],
  ['fastest', 'Last probe speed'],
  ['context', 'Largest context'],
  ['name', 'Name'],
]

function cleanIds(value, limit) {
  if (!Array.isArray(value)) return []
  return [...new Set(value.filter((id) => (
    typeof id === 'string'
    && id.length <= 200
    && /^[A-Za-z0-9._:/-]+$/.test(id)
  )))].slice(0, limit)
}

function readPreferences() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw || raw.length > MAX_STORED_BYTES) return { favorites: [], recent: [] }
    const parsed = JSON.parse(raw)
    return {
      favorites: cleanIds(parsed?.favorites, MAX_FAVORITES),
      recent: cleanIds(parsed?.recent, MAX_RECENT),
    }
  } catch {
    return { favorites: [], recent: [] }
  }
}

function writePreferences(preferences) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences)) } catch {}
}

function contextLabel(tokens) {
  if (!tokens) return 'Unknown context'
  return tokens >= 1000 ? `${Math.round(tokens / 1000)}K context` : `${tokens} context`
}

function checkedLabel(value) {
  if (!value) return 'Availability check time unavailable'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Availability check time unavailable'
  return `Checked ${date.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })}`
}

function modelSearchText(model) {
  return [
    model.name, model.vendor, model.id, model.description, model.purpose,
    model.best_for, model.performance?.latency_band,
  ]
    .filter(Boolean).join(' ').toLocaleLowerCase()
}

function probeLatencyLabel(model, prefix = '') {
  const milliseconds = model.performance?.probe_latency_ms
  if (!Number.isFinite(milliseconds)) return 'Not measured'
  const seconds = milliseconds / 1000
  const value = seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)
  return `${prefix}${value}s probe`
}

function comparisonValue(model, field) {
  const capabilities = model.capabilities || {}
  if (field === 'best_for') return model.best_for || 'General use'
  if (field === 'purpose') return model.purpose || 'assistant'
  if (field === 'latency') return probeLatencyLabel(model)
  if (field === 'context') return contextLabel(model.context)
  if (field === 'inputs') return (capabilities.input_modalities || ['text']).join(', ')
  if (field === 'images') {
    return capabilities.max_images
      ? `Up to ${capabilities.max_images}`
      : 'Not supported'
  }
  if (field === 'formats') {
    const formats = (capabilities.attachment_extensions || []).map((item) => item.toUpperCase())
    return formats.length ? formats.join(', ') : 'Text only'
  }
  return '—'
}

export default function ModelExplorer({
  models, currentModelId, availabilityCheckedAt, disabled = false, onSelect,
}) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [purpose, setPurpose] = useState('all')
  const [sortBy, setSortBy] = useState('recommended')
  const [favoritesOnly, setFavoritesOnly] = useState(false)
  const [preferences, setPreferences] = useState(readPreferences)
  const [compareIds, setCompareIds] = useState([])
  const [choosingId, setChoosingId] = useState(null)
  const triggerRef = useRef(null)
  const dialogRef = useRef(null)
  const searchRef = useRef(null)
  const resultsRef = useRef(null)

  function updatePreferences(updater) {
    setPreferences((previous) => {
      const candidate = updater(previous)
      const next = {
        favorites: cleanIds(candidate.favorites, MAX_FAVORITES),
        recent: cleanIds(candidate.recent, MAX_RECENT),
      }
      writePreferences(next)
      return next
    })
  }

  useEffect(() => {
    function syncPreferences(event) {
      if (event.key === STORAGE_KEY) setPreferences(readPreferences())
    }
    window.addEventListener('storage', syncPreferences)
    return () => window.removeEventListener('storage', syncPreferences)
  }, [])

  useEffect(() => {
    if (!open) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    searchRef.current?.focus()

    function handleDialogKeys(event) {
      if (event.key === 'Escape') {
        event.preventDefault()
        setOpen(false)
        triggerRef.current?.focus()
        return
      }
      if (event.key !== 'Tab') return
      const focusable = [...dialogRef.current.querySelectorAll(
        'button:not(:disabled), input:not(:disabled), [href], select:not(:disabled)',
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

    document.addEventListener('keydown', handleDialogKeys)
    return () => {
      document.body.style.overflow = previousOverflow
      document.removeEventListener('keydown', handleDialogKeys)
    }
  }, [open])

  useEffect(() => {
    resultsRef.current?.scrollTo({ top: 0 })
  }, [favoritesOnly, purpose, query, sortBy])

  const visibleModels = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase()
    const favoriteSet = new Set(preferences.favorites)
    const recentIndex = new Map(preferences.recent.map((id, index) => [id, index]))
    return models
      .filter((model) => purpose === 'all' || (model.purpose || 'assistant') === purpose)
      .filter((model) => !favoritesOnly || favoriteSet.has(model.id))
      .filter((model) => !normalizedQuery || modelSearchText(model).includes(normalizedQuery))
      .map((model, index) => ({ model, index }))
      .sort((a, b) => {
        const favoriteDelta = Number(favoriteSet.has(b.model.id)) - Number(favoriteSet.has(a.model.id))
        if (favoriteDelta) return favoriteDelta
        if (sortBy === 'fastest') {
          const aLatency = a.model.performance?.probe_latency_ms ?? Number.MAX_SAFE_INTEGER
          const bLatency = b.model.performance?.probe_latency_ms ?? Number.MAX_SAFE_INTEGER
          return aLatency - bLatency || a.index - b.index
        }
        if (sortBy === 'context') {
          return (b.model.context || 0) - (a.model.context || 0) || a.index - b.index
        }
        if (sortBy === 'name') return a.model.name.localeCompare(b.model.name)
        const recommendationDelta = Number(Boolean(b.model.recommended))
          - Number(Boolean(a.model.recommended))
        if (recommendationDelta) return recommendationDelta
        const aRecent = recentIndex.get(a.model.id) ?? Number.MAX_SAFE_INTEGER
        const bRecent = recentIndex.get(b.model.id) ?? Number.MAX_SAFE_INTEGER
        if (aRecent !== bRecent) return aRecent - bRecent
        const aLatency = a.model.performance?.probe_latency_ms ?? Number.MAX_SAFE_INTEGER
        const bLatency = b.model.performance?.probe_latency_ms ?? Number.MAX_SAFE_INTEGER
        return aLatency - bLatency || a.index - b.index
      })
      .map(({ model }) => model)
  }, [favoritesOnly, models, preferences, purpose, query, sortBy])

  const comparedModels = compareIds
    .map((id) => models.find((model) => model.id === id))
    .filter(Boolean)

  function toggleFavorite(modelId) {
    updatePreferences((previous) => {
      const exists = previous.favorites.includes(modelId)
      return {
        ...previous,
        favorites: exists
          ? previous.favorites.filter((id) => id !== modelId)
          : [modelId, ...previous.favorites],
      }
    })
  }

  function toggleCompare(modelId) {
    setCompareIds((ids) => ids.includes(modelId)
      ? ids.filter((id) => id !== modelId)
      : [...ids, modelId].slice(0, MAX_COMPARE))
  }

  function rememberRecent(modelId) {
    if (!modelId || !models.some((model) => model.id === modelId)) return
    updatePreferences((previous) => ({
      ...previous,
      recent: [modelId, ...previous.recent.filter((id) => id !== modelId)],
    }))
  }

  async function chooseModel(modelId) {
    if (disabled || choosingId) return
    setChoosingId(modelId)
    try {
      const selected = await onSelect(modelId)
      if (selected !== false) {
        rememberRecent(modelId)
        setOpen(false)
        triggerRef.current?.focus()
      }
    } finally {
      setChoosingId(null)
    }
  }

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className="icon model-explorer-trigger"
        aria-label="Open model explorer"
        aria-haspopup="dialog"
        aria-expanded={open}
        disabled={disabled || models.length === 0}
        onClick={() => {
          rememberRecent(currentModelId)
          setOpen(true)
        }}
        title="Search, favorite, and compare models"
      >⌘</button>

      {open && (
        <div className="model-explorer-backdrop" onMouseDown={(event) => {
          if (event.target === event.currentTarget) {
            setOpen(false)
            triggerRef.current?.focus()
          }
        }}>
          <section
            ref={dialogRef}
            className="model-explorer"
            role="dialog"
            aria-modal="true"
            aria-labelledby="model-explorer-title"
          >
            <header className="model-explorer-header">
              <div>
                <h2 id="model-explorer-title">Choose a model</h2>
                <p>{models.length} available · {checkedLabel(availabilityCheckedAt)}</p>
              </div>
              <button
                type="button"
                className="icon"
                aria-label="Close model explorer"
                onClick={() => {
                  setOpen(false)
                  triggerRef.current?.focus()
                }}
              >×</button>
            </header>

            <div className="model-explorer-tools">
              <label className="model-search">
                <span aria-hidden="true">⌕</span>
                <span className="sr-only">Search models</span>
                <input
                  ref={searchRef}
                  type="search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value.slice(0, 120))}
                  placeholder="Search name, vendor, capability…"
                  autoComplete="off"
                />
              </label>
              <button
                type="button"
                className={favoritesOnly ? 'filter-chip active' : 'filter-chip'}
                aria-pressed={favoritesOnly}
                onClick={() => setFavoritesOnly((value) => !value)}
              >★ Favorites</button>
              <label className="model-sort">
                <span className="sr-only">Sort models</span>
                <select
                  aria-label="Sort models"
                  value={sortBy}
                  onChange={(event) => setSortBy(event.target.value)}
                >
                  {SORTS.map(([value, label]) => (
                    <option key={value} value={value}>{label}</option>
                  ))}
                </select>
              </label>
            </div>

            <div className="purpose-filters" role="group" aria-label="Filter models by purpose">
              {PURPOSES.map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  className={purpose === id ? 'filter-chip active' : 'filter-chip'}
                  aria-pressed={purpose === id}
                  onClick={() => setPurpose(id)}
                >{label}</button>
              ))}
            </div>

            <div className="model-explorer-body">
              <div ref={resultsRef} className="model-results" aria-live="polite">
                {visibleModels.length === 0 && (
                  <div className="empty-list">No available models match these filters.</div>
                )}
                {visibleModels.map((model) => {
                  const capabilities = model.capabilities || {}
                  const favorite = preferences.favorites.includes(model.id)
                  const recent = preferences.recent.includes(model.id)
                  const compared = compareIds.includes(model.id)
                  const comparisonFull = compareIds.length >= MAX_COMPARE && !compared
                  return (
                    <article
                      key={model.id}
                      className={`model-card ${model.id === currentModelId ? 'selected' : ''}`}
                    >
                      <button
                        type="button"
                        className="model-card-select"
                        onClick={() => chooseModel(model.id)}
                        disabled={disabled || Boolean(choosingId)}
                        aria-label={`Use ${model.name}`}
                      >
                        <span className="model-card-title">
                          <strong>{model.name}</strong>
                          {model.id === currentModelId && <span className="current-pill">Current</span>}
                          {recent && model.id !== currentModelId && <span className="recent-pill">Recent</span>}
                        </span>
                        <span className="model-card-vendor">{model.vendor} · {model.id}</span>
                        <span className="model-card-description">{model.description}</span>
                        <span className="model-card-guidance">
                          <strong>Best for</strong> {model.best_for || 'General use'}
                        </span>
                        <span className="model-card-badges">
                          {model.recommended && <span className="positive">Recommended</span>}
                          <span>{model.purpose || 'assistant'}</span>
                          <span>{contextLabel(model.context)}</span>
                          <span>{capabilities.max_images ? `Images × ${capabilities.max_images}` : 'Text + documents'}</span>
                          {model.performance && (
                            <span
                              className={`speed-${model.performance.latency_band}`}
                              title="One synthetic 1-token availability probe; not a quality benchmark"
                            >{probeLatencyLabel(model)}</span>
                          )}
                        </span>
                      </button>
                      <div className="model-card-actions">
                        <button
                          type="button"
                          className={`favorite-toggle ${favorite ? 'active' : ''}`}
                          aria-pressed={favorite}
                          aria-label={`${favorite ? 'Remove' : 'Add'} ${model.name} ${favorite ? 'from' : 'to'} favorites`}
                          onClick={() => toggleFavorite(model.id)}
                        >{favorite ? '★' : '☆'}</button>
                        <label className={comparisonFull ? 'compare-toggle disabled' : 'compare-toggle'}>
                          <input
                            type="checkbox"
                            checked={compared}
                            disabled={comparisonFull}
                            onChange={() => toggleCompare(model.id)}
                            aria-label={`Compare ${model.name}`}
                          />
                          Compare
                        </label>
                      </div>
                    </article>
                  )
                })}
              </div>

              {comparedModels.length > 0 && (
                <aside className="model-comparison" aria-label="Model comparison">
                  <div className="comparison-heading">
                    <div>
                      <strong>Comparison</strong>
                      <small>{comparedModels.length}/{MAX_COMPARE} selected</small>
                    </div>
                    <button type="button" className="link" onClick={() => setCompareIds([])}>Clear</button>
                  </div>
                  <div className="comparison-table">
                    {comparedModels.map((model) => (
                      <div className="comparison-column" key={model.id}>
                        <strong>{model.name}</strong>
                        {[
                          ['Best for', 'best_for'],
                          ['Purpose', 'purpose'],
                          ['Last probe', 'latency'],
                          ['Context', 'context'],
                          ['Inputs', 'inputs'],
                          ['Images', 'images'],
                          ['Formats', 'formats'],
                        ].map(([label, field]) => (
                          <div key={field}>
                            <small>{label}</small>
                            <span>{comparisonValue(model, field)}</span>
                          </div>
                        ))}
                        <button type="button" onClick={() => chooseModel(model.id)} disabled={Boolean(choosingId)}>
                          {model.id === currentModelId ? 'Selected' : 'Use model'}
                        </button>
                      </div>
                    ))}
                  </div>
                </aside>
              )}
            </div>
            <p className="model-probe-note">
              Probe latency is one synthetic 1-token availability check, not a quality benchmark.
            </p>
          </section>
        </div>
      )}
    </>
  )
}
