import { useEffect, useState } from 'react'

const STORAGE_KEY = 'aichat-theme'
const VALID_PREFERENCES = new Set(['system', 'dark', 'light'])

function initialPreference() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    return VALID_PREFERENCES.has(stored) ? stored : 'system'
  } catch {
    return 'system'
  }
}

function prefersLightTheme() {
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ?? false
}

export default function useThemePreference() {
  const [preference, setPreference] = useState(initialPreference)
  const [systemLight, setSystemLight] = useState(prefersLightTheme)
  const resolvedTheme = preference === 'system'
    ? (systemLight ? 'light' : 'dark')
    : preference

  useEffect(() => {
    const media = window.matchMedia?.('(prefers-color-scheme: light)')
    if (!media) return undefined
    const update = (event) => setSystemLight(event.matches)
    media.addEventListener?.('change', update)
    return () => media.removeEventListener?.('change', update)
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = resolvedTheme
    document.documentElement.dataset.themePreference = preference
    try { localStorage.setItem(STORAGE_KEY, preference) } catch {}
  }, [preference, resolvedTheme])

  return [preference, setPreference, resolvedTheme]
}
