import { useEffect, useState } from 'react'

export const PRIVACY_NOTICE_VERSION = '2026-10-20.1'

const SECURITY_CONTACT = 'https://github.com/Alexandru2984/nvidia_api/security/advisories/new'

function ThemeToggle({ theme, onChange }) {
  return (
    <button
      type="button"
      className="privacy-theme-toggle"
      onClick={() => onChange(theme === 'dark' ? 'light' : 'dark')}
      aria-label={`Use ${theme === 'dark' ? 'light' : 'dark'} theme`}
    >
      {theme === 'dark' ? '☀ Light' : '☾ Dark'}
    </button>
  )
}

export default function PrivacyNotice() {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('aichat-theme') === 'light' ? 'light' : 'dark' }
    catch { return 'dark' }
  })

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.title = 'Privacy & data · AI Chat Hub'
    try { localStorage.setItem('aichat-theme', theme) } catch {}
  }, [theme])

  return (
    <div className="privacy-page">
      <a className="privacy-skip-link" href="#privacy-content">Skip to privacy notice</a>
      <header className="privacy-site-header">
        <a className="privacy-brand" href="/" aria-label="AI Chat Hub home">
          <span className="brand-mark" aria-hidden="true">N</span>
          <span>
            <strong>AI Chat Hub</strong>
            <small>Privacy &amp; data</small>
          </span>
        </a>
        <ThemeToggle theme={theme} onChange={setTheme} />
      </header>

      <main id="privacy-content" className="privacy-main">
        <section className="privacy-hero" aria-labelledby="privacy-title">
          <p className="privacy-eyebrow">Technical transparency notice</p>
          <h1 id="privacy-title">Know where your data goes.</h1>
          <p className="privacy-lead">
            AI Chat Hub stores account and chat data on its self-hosted service. Content leaves
            that service only for the specific delivery and AI flows described below.
          </p>
          <div className="privacy-version">
            Version {PRIVACY_NOTICE_VERSION} <span aria-hidden="true">·</span> Effective 20 October 2026
          </div>
        </section>

        <aside className="privacy-status" aria-labelledby="privacy-status-title">
          <div className="privacy-status-icon" aria-hidden="true">!</div>
          <div>
            <h2 id="privacy-status-title">Important governance gaps</h2>
            <p>
              This page documents verified technical behavior; it is not legal advice, a consent
              form, or evidence of a completed vendor review. The operator/controller identity,
              dedicated privacy contact, legal basis, NVIDIA DPA, processing region,
              retention/training terms, and production entitlement are not yet evidenced in the
              project. Do not submit personal, confidential, or third-party data you are not
              authorized to share.
            </p>
          </div>
        </aside>

        <nav className="privacy-nav" aria-label="Privacy notice sections">
          <a href="#data">Data handled</a>
          <a href="#destinations">Where it goes</a>
          <a href="#retention">Retention</a>
          <a href="#controls">Your controls</a>
          <a href="#open-decisions">Open decisions</a>
        </nav>

        <section className="privacy-section" id="data">
          <div className="privacy-section-heading">
            <p className="privacy-section-number">01</p>
            <div>
              <h2>Data the service handles</h2>
              <p>Only the data needed for accounts, conversations, delivery, and abuse controls.</p>
            </div>
          </div>
          <div className="privacy-card-grid">
            <article className="privacy-card">
              <h3>Account &amp; security</h3>
              <p>
                Username, email address, password hash, email verification and reset state, 2FA
                configuration, recovery-code hashes, session records, and security audit events.
              </p>
            </article>
            <article className="privacy-card">
              <h3>Chats &amp; files</h3>
              <p>
                Prompts, assistant responses, conversation settings and titles, uploaded files,
                extracted document text, generated images, and inclusion choices.
              </p>
            </article>
            <article className="privacy-card">
              <h3>Usage &amp; operations</h3>
              <p>
                Request and token counters, storage totals, generation status, privacy-minimized
                security events, and bounded session device/network metadata.
              </p>
            </article>
          </div>
        </section>

        <section className="privacy-section" id="destinations">
          <div className="privacy-section-heading">
            <p className="privacy-section-number">02</p>
            <div>
              <h2>Where data goes</h2>
              <p>The application does not sell user data. These are its verified service boundaries.</p>
            </div>
          </div>
          <div className="privacy-table-wrap" tabIndex="0" role="region" aria-label="Data destinations">
            <table className="privacy-table">
              <thead>
                <tr><th>Destination</th><th>Data and purpose</th><th>Known limits</th></tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row">Self-hosted service</th>
                  <td>Account, chat, attachment, preference, usage, and security data for the core service.</td>
                  <td>Protected by owner scoping, quotas, encryption in transit, restricted services, and local access controls.</td>
                </tr>
                <tr>
                  <th scope="row">NVIDIA</th>
                  <td>
                    The selected prompt, relevant chat context, included documents/images, and
                    image-generation settings are sent only when you request generation.
                  </td>
                  <td>Provider retention, training, region, DPA, and production entitlement remain unconfirmed.</td>
                </tr>
                <tr>
                  <th scope="row">Self-hosted mailcow</th>
                  <td>Your email address and verification or password-reset message for account delivery.</td>
                  <td>SMTP uses STARTTLS; provider log retention is not published here.</td>
                </tr>
                <tr>
                  <th scope="row">Cloudflare</th>
                  <td>Public traffic transport and network/request/security metadata at the edge.</td>
                  <td>Account-level retention, DPA, and breach terms require operator review.</td>
                </tr>
                <tr>
                  <th scope="row">Local inspection</th>
                  <td>ClamAV and the document parser inspect uploaded bytes on the host before storage or provider use.</td>
                  <td>This inspection does not introduce another third-party data destination.</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="privacy-note">
            The application code embeds no cross-origin analytics. Cloudflare Browser Insights
            injection has been observed at the edge but is blocked by the current Content Security
            Policy; dashboard-side removal remains an open operator action.
          </p>
          <p className="privacy-provider-links">
            Read NVIDIA's{' '}
            <a href="https://www.nvidia.com/en-us/about-nvidia/privacy-policy/" target="_blank" rel="noreferrer">
              privacy policy
            </a>{' '}and{' '}
            <a href="https://developer.nvidia.com/legal/terms" target="_blank" rel="noreferrer">
              developer terms
            </a>.
          </p>
        </section>

        <section className="privacy-section" id="retention">
          <div className="privacy-section-heading">
            <p className="privacy-section-number">03</p>
            <div>
              <h2>Retention in the application</h2>
              <p>Current defaults and user-selectable periods implemented in the service.</p>
            </div>
          </div>
          <div className="privacy-table-wrap" tabIndex="0" role="region" aria-label="Data retention periods">
            <table className="privacy-table privacy-retention-table">
              <thead><tr><th>Data</th><th>Current retention</th></tr></thead>
              <tbody>
                <tr><th scope="row">Active chats and linked files</th><td>Until you delete them or delete the account.</td></tr>
                <tr><th scope="row">Archived chats</th><td>Your choice: keep until deletion, or remove after 30, 90, 180, or 365 inactive days.</td></tr>
                <tr><th scope="row">Unattached uploads</th><td>30 days.</td></tr>
                <tr><th scope="row">User-linked AI usage</th><td>90 days; global aggregate usage is retained 400 days.</td></tr>
                <tr><th scope="row">Generation job metadata</th><td>7 days after completion.</td></tr>
                <tr><th scope="row">Login sessions</th><td>14-day sliding cookie lifetime, capped at 30 days from sign-in.</td></tr>
                <tr><th scope="row">Invite / privileged audit</th><td>90 days for invitation audit; 365 days for privileged admin audit.</td></tr>
                <tr><th scope="row">Upload-attempt metadata</th><td>24 hours.</td></tr>
                <tr><th scope="row">Verification/reset codes</th><td>Codes expire after 30 minutes and are removed by scheduled cleanup.</td></tr>
                <tr><th scope="row">Scheduled account deletion</th><td>7-day grace period before live account data is deleted.</td></tr>
                <tr><th scope="row">Database backups</th><td>The newest 7 daily local backups are kept by default.</td></tr>
              </tbody>
            </table>
          </div>
          <p className="privacy-note">
            Data deleted from the live service may remain in those rotating backups until expiry.
            A backup restoration must reapply deletion obligations. Exact system-journal and
            external-provider retention are not represented as settled here.
          </p>
        </section>

        <section className="privacy-section" id="controls">
          <div className="privacy-section-heading">
            <p className="privacy-section-number">04</p>
            <div>
              <h2>Your controls</h2>
              <p>Authenticated tools available in the application today.</p>
            </div>
          </div>
          <ul className="privacy-control-list">
            <li><strong>Export:</strong> download an account JSON export or an individual conversation export.</li>
            <li><strong>Delete:</strong> remove files and conversations, delete immediately, or schedule account deletion with a grace period.</li>
            <li><strong>Retention:</strong> choose automatic deletion for inactive archived chats.</li>
            <li><strong>Provider choice:</strong> cancel before the first NVIDIA-bound request and include or exclude supported files per message.</li>
            <li><strong>Account security:</strong> enable 2FA, review sessions, and revoke other sessions.</li>
          </ul>
          <a className="privacy-primary-link" href="/">Open AI Chat Hub</a>
        </section>

        <section className="privacy-section privacy-open-section" id="open-decisions">
          <div className="privacy-section-heading">
            <p className="privacy-section-number">05</p>
            <div>
              <h2>Open governance decisions</h2>
              <p>These items must be completed by the operator before the privacy posture can be called complete.</p>
            </div>
          </div>
          <ul className="privacy-gap-list">
            <li>Publish the responsible operator/controller identity and a dedicated privacy contact.</li>
            <li>Document the legal basis, user-rights procedure, jurisdiction, and any age restrictions.</li>
            <li>Review and record NVIDIA retention, training, regional processing, DPA, breach terms, and production entitlement.</li>
            <li>Review Cloudflare and mail service contracts, retention, DPA, and incident-notification terms.</li>
            <li>Disable Browser Insights in the Cloudflare dashboard and verify it is absent at the edge.</li>
            <li>Define exact journal/off-host security-log retention and encrypted off-host backup governance.</li>
          </ul>
        </section>

        <section className="privacy-section privacy-contact" aria-labelledby="privacy-contact-title">
          <h2 id="privacy-contact-title">Questions and reports</h2>
          <p>
            No dedicated privacy contact is currently published; this is a known gap. Use the
            authenticated export/deletion controls for your account. Report security issues
            privately through the{' '}
            <a href={SECURITY_CONTACT} target="_blank" rel="noreferrer">GitHub security advisory form</a>,
            not a public issue.
          </p>
        </section>
      </main>

      <footer className="privacy-footer">
        <p>AI Chat Hub · Privacy notice {PRIVACY_NOTICE_VERSION}</p>
        <a href="/">Back to the application</a>
      </footer>
    </div>
  )
}
