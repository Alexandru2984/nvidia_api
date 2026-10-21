import { useEffect, useMemo, useRef, useState } from 'react'
import {
  attachmentCompatibilityForModel,
  attachmentCompatibilityReasonSummary,
} from './modelCapabilities'

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

function restoreFocus(returnFocusRef, triggerRef) {
  const requestedTarget = returnFocusRef.current
  requestAnimationFrame(() => {
    const target = requestedTarget?.isConnected && !requestedTarget.disabled
      ? requestedTarget
      : triggerRef.current
    target?.focus()
  })
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

function comparisonValue(model, field, attachments) {
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
  if (field === 'current_files') {
    if (attachments.length === 0) return 'No files selected'
    const compatibility = attachmentCompatibilityForModel(attachments, model)
    const reasons = attachmentCompatibilityReasonSummary(compatibility)
    return compatibility.compatible
      ? `All ${attachments.length} supported`
      : `${compatibility.incompatible.length} of ${attachments.length} incompatible${reasons ? ` · ${reasons}` : ''}`
  }
  return '—'
}

export default function ModelExplorer({
  models, currentModelId, defaultModelId, attachments = [], availabilityCheckedAt, availability,
  disabled = false, openRequest, onSelect, onSetDefault,
}) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [purpose, setPurpose] = useState('all')
  const [sortBy, setSortBy] = useState('recommended')
  const [favoritesOnly, setFavoritesOnly] = useState(false)
  const [compatibleOnly, setCompatibleOnly] = useState(false)
  const [preferences, setPreferences] = useState(readPreferences)
  const [compareIds, setCompareIds] = useState([])
  const [choosingId, setChoosingId] = useState(null)
  const [defaultBusyId, setDefaultBusyId] = useState(null)
  const [preferenceNotice, setPreferenceNotice] = useState(null)
  const [preferenceError, setPreferenceError] = useState(null)
  const triggerRef = useRef(null)
  const returnFocusRef = useRef(null)
  const openRequestId = openRequest?.id || 0
  const handledOpenRequestRef = useRef(openRequestId)
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
    if (!openRequestId || openRequestId === handledOpenRequestRef.current) return
    handledOpenRequestRef.current = openRequestId
    const activeElement = document.activeElement
    returnFocusRef.current = activeElement && activeElement !== document.body
      ? activeElement
      : triggerRef.current
    setQuery('')
    setPurpose('all')
    setFavoritesOnly(false)
    setCompatibleOnly(Boolean(openRequest?.compatibleOnly && attachments.length))
    setOpen(true)
  }, [attachments.length, openRequest?.compatibleOnly, openRequestId])

  useEffect(() => {
    if (!open) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    searchRef.current?.focus()

    function handleDialogKeys(event) {
      if (event.key === 'Escape') {
        event.preventDefault()
        setOpen(false)
        restoreFocus(returnFocusRef, triggerRef)
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
  }, [compatibleOnly, favoritesOnly, purpose, query, sortBy])

  const compatibilityById = useMemo(() => new Map(models.map((model) => [
    model.id,
    attachmentCompatibilityForModel(attachments, model),
  ])), [attachments, models])

  const purposeCounts = useMemo(() => models.reduce((counts, model) => {
    const modelPurpose = model.purpose || 'assistant'
    counts.set(modelPurpose, (counts.get(modelPurpose) || 0) + 1)
    return counts
  }, new Map()), [models])
  const availablePurposes = PURPOSES.filter(([id]) => id === 'all' || purposeCounts.has(id))

  const compatibleModelCount = attachments.length
    ? models.filter((model) => compatibilityById.get(model.id)?.compatible).length
    : models.length

  const visibleModels = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase()
    const favoriteSet = new Set(preferences.favorites)
    const recentIndex = new Map(preferences.recent.map((id, index) => [id, index]))
    return models
      .filter((model) => purpose === 'all' || (model.purpose || 'assistant') === purpose)
      .filter((model) => !favoritesOnly || favoriteSet.has(model.id))
      .filter((model) => !compatibleOnly || compatibilityById.get(model.id)?.compatible)
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
  }, [compatibleOnly, compatibilityById, favoritesOnly, models, preferences, purpose, query, sortBy])

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

  function clearModelFilters() {
    setQuery('')
    setPurpose('all')
    setFavoritesOnly(false)
    setCompatibleOnly(false)
    requestAnimationFrame(() => searchRef.current?.focus())
  }

  async function chooseModel(modelId) {
    if (disabled || choosingId) return
    setChoosingId(modelId)
    try {
      const selected = await onSelect(modelId)
      if (selected !== false) {
        rememberRecent(modelId)
        setOpen(false)
        restoreFocus(returnFocusRef, triggerRef)
      }
    } finally {
      setChoosingId(null)
    }
  }

  async function setDefaultModel(model) {
    if (disabled || choosingId || defaultBusyId || model.id === defaultModelId) return
    setDefaultBusyId(model.id)
    setPreferenceError(null)
    setPreferenceNotice(null)
    try {
      await onSetDefault(model.id)
      setPreferenceNotice(`${model.name} is now the default for new conversations.`)
    } catch (error) {
      setPreferenceError(error.message || 'Could not update the default model.')
    } finally {
      setDefaultBusyId(null)
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
        onClick={(event) => {
          returnFocusRef.current = event.currentTarget
          rememberRecent(currentModelId)
          setOpen(true)
        }}
        title="Search, favorite, and compare models"
      >⌘</button>

      {open && (
        <div className="model-explorer-backdrop" onMouseDown={(event) => {
          if (event.target === event.currentTarget) {
            setOpen(false)
            restoreFocus(returnFocusRef, triggerRef)
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
                <p>
                  {models.length} of {availability?.catalog_models || models.length} available ·{' '}
                  {checkedLabel(availability?.checked_at || availabilityCheckedAt)}
                </p>
              </div>
              <button
                type="button"
                className="icon"
                aria-label="Close model explorer"
                onClick={() => {
                  setOpen(false)
                  restoreFocus(returnFocusRef, triggerRef)
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
              {attachments.length > 0 && (
                <button
                  type="button"
                  className={compatibleOnly ? 'filter-chip active' : 'filter-chip'}
                  aria-pressed={compatibleOnly}
                  onClick={() => setCompatibleOnly((value) => !value)}
                >✓ Fits {attachments.length} current file{attachments.length === 1 ? '' : 's'}</button>
              )}
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

            {attachments.length > 0 && (
              <div className="model-file-fit-summary" role="status">
                <strong>{attachments.length} selected file{attachments.length === 1 ? '' : 's'}</strong>
                <span>
                  {compatibleModelCount} of {models.length} available model{models.length === 1 ? '' : 's'}
                  {' '}can use all of them. Excluded files are not considered.
                </span>
              </div>
            )}

            {preferenceNotice && (
              <div className="model-preference-feedback" role="status">{preferenceNotice}</div>
            )}
            {preferenceError && (
              <div className="model-preference-feedback error" role="alert">{preferenceError}</div>
            )}

            <div className="purpose-filters" role="group" aria-label="Filter models by purpose">
              {availablePurposes.map(([id, label]) => {
                const count = id === 'all' ? models.length : purposeCounts.get(id)
                return (
                  <button
                    key={id}
                    type="button"
                    className={purpose === id ? 'filter-chip active' : 'filter-chip'}
                    aria-pressed={purpose === id}
                    onClick={() => setPurpose(id)}
                  >{label} <span className="filter-count">{count}</span></button>
                )
              })}
            </div>

            <div className="model-explorer-body">
              <div ref={resultsRef} className="model-results" aria-live="polite">
                {visibleModels.length === 0 && (
                  <div className="empty-list model-empty">
                    <span>
                      {compatibleOnly
                        ? 'No available model can use every selected file. Exclude or remove incompatible files.'
                        : 'No available models match these filters.'}
                    </span>
                    <button type="button" className="link" onClick={clearModelFilters}>
                      {compatibleOnly ? 'Show all models' : 'Clear filters'}
                    </button>
                  </div>
                )}
                {visibleModels.map((model) => {
                  const capabilities = model.capabilities || {}
                  const fileCompatibility = compatibilityById.get(model.id)
                  const incompatibilityReasons = attachmentCompatibilityReasonSummary(fileCompatibility)
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
                          {model.id === defaultModelId && <span className="default-pill">Default</span>}
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
                          {attachments.length > 0 && (
                            <span className={fileCompatibility?.compatible ? 'positive' : 'warning'}>
                              {fileCompatibility?.compatible
                                ? 'Fits current files'
                                : `${fileCompatibility?.incompatible.length || attachments.length} file${(fileCompatibility?.incompatible.length || attachments.length) === 1 ? '' : 's'} incompatible${incompatibilityReasons ? ` · ${incompatibilityReasons}` : ''}`}
                            </span>
                          )}
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
                          className="model-default-toggle"
                          disabled={
                            disabled || Boolean(choosingId) || Boolean(defaultBusyId)
                            || model.id === defaultModelId
                          }
                          aria-label={
                            model.id === defaultModelId
                              ? `${model.name} is the default model`
                              : `Set ${model.name} as default`
                          }
                          onClick={() => setDefaultModel(model)}
                        >
                          {defaultBusyId === model.id
                            ? 'Saving…'
                            : model.id === defaultModelId ? 'Default' : 'Set default'}
                        </button>
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
                          ['Current files', 'current_files'],
                        ].map(([label, field]) => (
                          <div key={field}>
                            <small>{label}</small>
                            <span>{comparisonValue(model, field, attachments)}</span>
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
              {availability?.state === 'degraded' && (
                <span> Some checks were inconclusive; last verified availability was retained.</span>
              )}
            </p>
          </section>
        </div>
      )}
    </>
  )
}
