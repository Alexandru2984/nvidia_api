import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import PrivacyNotice from './PrivacyNotice.jsx'

const normalizedPath = window.location.pathname.replace(/\/+$/, '') || '/'
const root = normalizedPath === '/privacy' ? <PrivacyNotice /> : <App />

createRoot(document.getElementById('root')).render(
  <StrictMode>
    {root}
  </StrictMode>,
)
