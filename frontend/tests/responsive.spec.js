import { test, expect } from '@playwright/test'
import { Buffer } from 'node:buffer'

async function mockAPI(
  page, signedIn = true, conversationModel = 'test/model', registrationMode = 'open',
  modelAvailability = {
    state: 'verified', checked_at: '2026-10-06T00:19:57Z', inconclusive_models: 0,
    unverified_models: 0, catalog_models: 2, available_models: 2, unavailable_models: 0,
  },
  providerDisclosureAccepted = true,
) {
  let disclosureAccepted = providerDisclosureAccepted
  let conversation = {
    id: 1, title: 'A useful conversation', model_id: conversationModel, message_count: 2,
    is_pinned: false, archived_at: null,
    created_at: '2026-10-05T12:00:00Z', updated_at: '2026-10-05T12:00:00Z',
    messages: [
      { id: 1, role: 'user', content: 'Explain this code', attachments: [] },
      { id: 2, role: 'assistant', content: '```js\nconst value = 42\n```\n\n' + 'longword'.repeat(70)
        + '\n\n![tracker](https://tracker.invalid/pixel)'
        + '\n\n[blocked script](javascript:window.__markdownExecuted=true)'
        + '\n\n![inline tracker](data:image/svg+xml;base64,PHN2Zy8+)'
        + '\n\n| A | B |\n|---|---|\n| first | second |', attachments: [] },
    ],
  }
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname
    if (path === '/api/conversations/' && route.request().method() === 'GET') {
      const view = url.searchParams.get('view') || 'active'
      const visible = view === 'all'
        || (view === 'archived' ? Boolean(conversation.archived_at) : !conversation.archived_at)
      return route.fulfill({ status: 200, json: {
        results: visible ? [conversation] : [],
        counts: {
          active: conversation.archived_at ? 0 : 1,
          archived: conversation.archived_at ? 1 : 0,
        },
        next_cursor: null,
      } })
    }
    if (path === '/api/conversations/1/' && route.request().method() === 'PATCH') {
      const patch = route.request().postDataJSON()
      const next = { ...conversation, ...patch, updated_at: '2026-10-05T12:01:00Z' }
      if (Object.hasOwn(patch, 'archived')) {
        next.archived_at = patch.archived ? '2026-10-05T12:01:00Z' : null
        if (patch.archived) next.is_pinned = false
        delete next.archived
      }
      conversation = next
      return route.fulfill({ status: 200, json: conversation })
    }
    if (path === '/api/attachments/upload/' && route.request().method() === 'POST') {
      return route.fulfill({ status: 201, json: {
        id: 900, kind: 'image', original_name: 'diagram.png', mime_type: 'image/png',
        size: 68, url: '/api/attachments/900/download/', has_text: false, deletable: true,
        deduplicated: false,
      } })
    }
    if (/^\/api\/attachments\/upload\/[0-9a-f-]{36}\/$/.test(path)
        && route.request().method() === 'DELETE') {
      return route.fulfill({ status: 204, body: '' })
    }
    if (/^\/api\/attachments\/(900|910)\/$/.test(path) && route.request().method() === 'DELETE') {
      return route.fulfill({ status: 204, body: '' })
    }
    if (path === '/api/provider-disclosure/' && route.request().method() === 'POST') {
      disclosureAccepted = true
      const { version } = route.request().postDataJSON()
      return route.fulfill({ status: 200, json: { provider_disclosure: {
        required_version: version, accepted: true, accepted_at: '2026-10-15T01:00:00Z',
      } } })
    }
    const data = {
      '/api/auth/me/': {
        username: signedIn ? 'alice' : null,
        registration_mode: registrationMode,
        ...(signedIn ? { provider_disclosure: {
          required_version: 1,
          accepted: disclosureAccepted,
          accepted_at: disclosureAccepted ? '2026-10-05T10:00:00Z' : null,
        } } : {}),
      },
      '/api/models/': {
        models: [
          {
            id: 'test/model', name: 'Test Vision', vendor: 'Test', vision: true,
            purpose: 'assistant', recommended: true, context: 128000,
            description: 'A capable test model with image input.',
            best_for: 'Image and document analysis',
            performance: {
              probe_latency_ms: 2400, latency_band: 'moderate', sample: 'synthetic_1_token',
            },
            capabilities: {
              input_modalities: ['text', 'document', 'image'],
              attachment_extensions: ['pdf', 'txt', 'md', 'docx', 'jpg', 'jpeg', 'png'],
              document_extensions: ['pdf', 'txt', 'md', 'docx'], documents_as_text: true,
              image_mime_types: ['image/jpeg', 'image/png'], max_images: 1,
              max_image_bytes: null,
            },
            generation: {
              temperature: { min: 0, max: 1, step: 0.1, default: 0.7 },
              max_tokens: { min: 64, max: 4096, step: 64, default: 1024 },
            },
          },
          {
            id: 'text/model', name: 'Text Only', vendor: 'Test', vision: false,
            purpose: 'assistant', recommended: true, context: 32000,
            description: 'A fast text-only test model.',
            best_for: 'General chat and document analysis',
            performance: {
              probe_latency_ms: 900, latency_band: 'fast', sample: 'synthetic_1_token',
            },
            capabilities: {
              input_modalities: ['text', 'document'],
              attachment_extensions: ['pdf', 'txt', 'md', 'docx'],
              document_extensions: ['pdf', 'txt', 'md', 'docx'], documents_as_text: true,
              image_mime_types: [], max_images: 0, max_image_bytes: null,
            },
            generation: {
              temperature: { min: 0, max: 1, step: 0.1, default: 0.7 },
              max_tokens: { min: 64, max: 8192, step: 64, default: 1024 },
            },
          },
        ],
        default: 'test/model',
        availability_checked_at: '2026-10-06T00:19:57Z',
        availability: modelAvailability,
        attachment_limits: {
          max_files_per_message: 8, max_file_bytes: 10485760,
          max_bytes_per_message: 20971520,
        },
      },
      '/api/conversations/1/': conversation,
      '/api/images/models/': { models: [], default: '' },
      '/api/attachments/': [],
      '/api/attachments/910/preview/': {
        text: 'Safe text <script>window.__previewExecuted = true</script>',
        characters: 58,
        truncated: false,
      },
      '/api/account/usage/': {
        storage_bytes: 5242880, storage_limit_bytes: 104857600, attachments: 0,
        conversations: 1, conversation_limit: 500, messages: 2, message_limit: 10000,
        message_limit_per_conversation: 2000,
        ai_today: {
          date: '2026-10-05', chat_requests: 4, chat_limit: 100, image_requests: 1, image_limit: 10,
          prompt_characters: 420, resets_at: '2026-10-06T00:00:00Z', enabled: true,
        },
      },
      '/api/account/chat-retention/': {
        archived_days: 0,
        choices: [
          { days: 0, label: 'Keep until I delete' },
          { days: 30, label: 'Delete after 30 days' },
          { days: 90, label: 'Delete after 90 days' },
          { days: 180, label: 'Delete after 180 days' },
          { days: 365, label: 'Delete after 365 days' },
        ],
        scope: 'archived_inactive_conversations',
      },
      '/api/account/deletion/': {
        scheduled: false, requested_at: null, execute_after: null, grace_days: 7,
      },
      '/api/auth/2fa/status/': { enabled: false, recovery_codes_remaining: 0 },
      '/api/auth/sessions/': [{ id: 'opaque-handle', current: true, ua: 'Browser', ip: '198.51.100.1', expires_at: '2026-11-01T00:00:00Z' }],
    }[path]
    return route.fulfill({ status: data ? 200 : 404, json: data || { error: 'Unexpected mock request' } })
  })
}

test('application shell contains no cross-origin scripts', async ({ page }) => {
  await mockAPI(page)
  await page.goto('/')
  await expect(page.locator('script[src^="http://"], script[src^="https://"]')).toHaveCount(0)
})

test('public privacy center is responsive and performs no API bootstrap', async ({ page }) => {
  const apiRequests = []
  page.on('request', (request) => {
    if (new URL(request.url()).pathname.startsWith('/api/')) apiRequests.push(request.url())
  })

  for (const width of [320, 1440]) {
    await page.setViewportSize({ width, height: 844 })
    await page.goto('/privacy/')
    await expect(page).toHaveTitle('Privacy & data · AI Chat Hub')
    await expect(page.getByRole('heading', { name: 'Know where your data goes.' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Important governance gaps' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Retention in the application' })).toBeVisible()
    await expect(page.getByText('90 days; global aggregate usage is retained 400 days.')).toBeVisible()
    await expect(page.getByText(/No dedicated privacy contact is currently published/)).toBeVisible()
    await expect(page.getByRole('link', { name: 'GitHub security advisory form' })).toHaveAttribute(
      'href', 'https://github.com/Alexandru2984/nvidia_api/security/advisories/new',
    )
    await expect(page.locator('[href^="javascript:"], [href^="data:"]')).toHaveCount(0)
    await expectNoPageOverflow(page)
    await page.screenshot({ path: `test-results/privacy-${width}.png` })
  }

  expect(apiRequests).toEqual([])
})

test('private file library rejects fabricated attachment URLs', async ({ page }) => {
  await mockAPI(page)
  await page.route('**/api/attachments/**', (route) => {
    const url = new URL(route.request().url())
    if (url.pathname !== '/api/attachments/' || route.request().method() !== 'GET') {
      return route.fallback()
    }
    return route.fulfill({ status: 200, json: {
      results: [
        {
          id: 701, kind: 'document', original_name: 'safe.txt', mime_type: 'text/plain',
          size: 12, url: '/api/attachments/701/download/', has_text: true, deletable: false,
        },
        {
          id: 702, kind: 'document', original_name: 'cross-origin.txt', mime_type: 'text/plain',
          size: 12, url: 'https://attacker.invalid/private', has_text: true, deletable: false,
        },
        {
          id: 703, kind: 'document', original_name: 'script.txt', mime_type: 'text/plain',
          size: 12, url: 'javascript:window.__attachmentExecuted=true', has_text: true, deletable: false,
        },
        {
          id: 704, kind: 'document', original_name: 'query.txt', mime_type: 'text/plain',
          size: 12, url: '/api/attachments/704/download/?next=https://attacker.invalid',
          has_text: true, deletable: false,
        },
      ],
      next_cursor: null,
    } })
  })

  await page.goto('/')
  await page.getByTitle('Settings', { exact: true }).click()
  await expect(page.getByRole('link', { name: 'safe.txt' })).toHaveAttribute(
    'href', '/api/attachments/701/download/',
  )
  for (const name of ['cross-origin.txt', 'script.txt', 'query.txt']) {
    await expect(page.getByText(name, { exact: true })).toBeVisible()
    await expect(page.getByRole('link', { name })).toHaveCount(0)
  }
  await expect(page.getByText('File link unavailable', { exact: false })).toHaveCount(3)
  await expect(page.locator('[href^="javascript:"], [href*="attacker.invalid"]')).toHaveCount(0)
  expect(await page.evaluate(() => window.__attachmentExecuted)).toBeUndefined()
})

test('message attachments never load cross-origin URLs from API data', async ({ page }) => {
  await mockAPI(page)
  const crossOriginRequests = []
  page.on('request', (request) => {
    if (request.url().includes('attacker.invalid')) crossOriginRequests.push(request.url())
  })
  await page.route(/\/api\/conversations\/1\/(?:\?.*)?$/, (route) => route.fulfill({ status: 200, json: {
    id: 1, title: 'A useful conversation', model_id: 'test/model', message_count: 1,
    is_pinned: false, archived_at: null,
    created_at: '2026-10-05T12:00:00Z', updated_at: '2026-10-05T12:00:00Z',
    messages: [{
      id: 1, role: 'user', content: 'untrusted attachment response',
      attachments: [{
        id: 705, kind: 'image', original_name: 'remote.png', mime_type: 'image/png',
        size: 68, url: 'https://attacker.invalid/pixel', has_text: false, deletable: false,
      }],
    }],
  } }))

  await page.goto('/')
  await page.getByRole('button', { name: /A useful conversation/ }).click()
  await expect(page.getByText('File link unavailable', { exact: true })).toBeVisible()
  await expect(page.locator('img[src*="attacker.invalid"], a[href*="attacker.invalid"]')).toHaveCount(0)
  expect(crossOriginRequests).toEqual([])
})

test('provider disclosure gates the first request and remains usable on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await mockAPI(page, true, 'test/model', 'open', undefined, false)
  let providerRequests = 0
  await page.route('**/api/conversations/1/messages/', (route) => {
    providerRequests += 1
    const userMessage = {
      id: 3, role: 'user', content: 'private prompt', attachments: [],
      created_at: '2026-10-15T01:00:01Z',
    }
    const assistantMessage = {
      id: 4, role: 'assistant', content: 'safe response', attachments: [],
      created_at: '2026-10-15T01:00:02Z',
    }
    return route.fulfill({
      status: 200,
      contentType: 'text/event-stream',
      body: `data: ${JSON.stringify({
        done: true,
        user_message: userMessage,
        assistant_message: assistantMessage,
        conversation: {
          id: 1, title: 'A useful conversation', model_id: 'test/model',
          message_count: 4, is_pinned: false, archived_at: null,
          created_at: '2026-10-05T12:00:00Z', updated_at: '2026-10-15T01:00:02Z',
        },
      })}\n\n`,
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByRole('button', { name: /A useful conversation/ }).click()
  await page.getByRole('textbox', { name: 'Message', exact: true }).fill('private prompt')
  const send = page.getByTitle('Send')
  await send.click()

  const dialog = page.getByRole('dialog', { name: 'Before your first AI request' })
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText('Only documents and images marked as included')
  await expect(dialog.getByRole('link', { name: 'privacy policy' })).toHaveAttribute(
    'href', 'https://www.nvidia.com/en-us/about-nvidia/privacy-policy/',
  )
  await expect(dialog.getByRole('link', { name: 'complete privacy notice' })).toHaveAttribute(
    'href', '/privacy/',
  )
  expect(providerRequests).toBe(0)
  await expectNoPageOverflow(page)
  await page.screenshot({ path: 'test-results/provider-disclosure-320.png' })

  await page.keyboard.press('Escape')
  await expect(dialog).toHaveCount(0)
  await expect(send).toBeFocused()
  await send.click()
  await dialog.getByRole('button', { name: 'I understand — continue' }).click()

  await expect(dialog).toHaveCount(0)
  await expect.poll(() => providerRequests).toBe(1)
  await expect(page.getByText('safe response')).toBeVisible()
  await expectNoPageOverflow(page)
})

test('stale disclosure text cannot accept a newer server version', async ({ page }) => {
  await mockAPI(page)
  let providerRequests = 0
  await page.route('**/api/conversations/1/messages/', (route) => {
    providerRequests += 1
    if (providerRequests === 1) {
      return route.fulfill({
        status: 428,
        json: {
          error: 'Review how your content is sent to NVIDIA before generating.',
          code: 'provider_disclosure_required',
          provider_disclosure: {
            required_version: 2, accepted: false, accepted_at: null,
          },
        },
      })
    }
    return route.abort()
  })

  await page.goto('/')
  await page.getByRole('button', { name: 'A useful conversation', exact: false }).first().click()
  const composer = page.getByRole('textbox', { name: 'Message', exact: true })
  await composer.fill('preserve this draft')
  await page.getByTitle('Send').click()

  const dialog = page.getByRole('dialog', { name: 'Before your first AI request' })
  await expect(dialog).toBeVisible()
  await expect(composer).toHaveValue('preserve this draft')
  await expect(dialog).toContainText(
    'This disclosure has changed. Reload the page to review its current text',
  )
  await expect(dialog.getByRole('button', { name: 'Reload to review' })).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'I understand — continue' })).toHaveCount(0)
  expect(providerRequests).toBe(1)
})

test('conversation settings enforce the selected model generation contract', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByRole('button', { name: /A useful conversation/ }).click()
  await page.getByTitle(/Conversation settings/).click()

  const panel = page.locator('.convo-settings')
  await expect(panel.locator('input[type="range"]')).toHaveAttribute('max', '1')
  await expect(panel.locator('input[type="number"]')).toHaveAttribute('max', '4096')
  await expect(panel).toContainText('up to 4,096 output tokens')
  await expectNoPageOverflow(page)
})

test('2FA enrollment sends and then clears the current password', async ({ page }) => {
  await mockAPI(page)
  const payloads = []
  await page.route('**/api/auth/2fa/enroll/', async (route) => {
    payloads.push(route.request().postDataJSON())
    if (payloads.length === 1) {
      await route.fulfill({ status: 401, json: { error: 'Wrong password.' } })
      return
    }
    await route.fulfill({ status: 200, json: {
      secret: 'JBSWY3DPEHPK3PXP',
      provisioning_uri: 'otpauth://totp/test',
      qr_data_url: 'data:image/svg+xml;base64,PHN2Zy8+',
    } })
  })
  await page.goto('/')
  await page.getByTitle('Settings', { exact: true }).click()
  const panel = page.getByRole('heading', { name: 'Two-factor authentication' }).locator('..')
  const password = panel.getByLabel('Current password', { exact: true })

  await password.fill('first-password')
  await panel.getByRole('button', { name: 'Enable 2FA' }).click()
  await expect(panel.getByText('Wrong password.')).toBeVisible()
  await expect(password).toHaveValue('')

  await password.fill('second-password')
  await panel.getByRole('button', { name: 'Enable 2FA' }).click()
  await expect(panel.getByAltText('2FA QR')).toBeVisible()
  expect(payloads).toEqual([
    { password: 'first-password' },
    { password: 'second-password' },
  ])
  await panel.getByRole('button', { name: 'Cancel' }).click()
  await expect(panel.getByLabel('Current password', { exact: true })).toHaveValue('')
})

test('expired session controls reauthenticate with 2FA and resume revocation', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  let otherActive = true
  let recentlyAuthenticated = false
  const reauthPayloads = []
  await page.route('**/api/auth/sessions/**', async (route) => {
    const url = new URL(route.request().url())
    if (url.pathname === '/api/auth/sessions/' && route.request().method() === 'GET') {
      const sessions = [{
        id: 'current-handle', current: true, ua: 'This browser', ip: '198.51.100.1',
        login_at: '2026-10-14T10:00:00Z', expires_at: '2026-11-01T00:00:00Z',
      }]
      if (otherActive) sessions.push({
        id: 'other-handle', current: false, ua: 'Unknown browser', ip: '203.0.113.9',
        login_at: '2026-10-13T10:00:00Z', expires_at: '2026-11-01T00:00:00Z',
      })
      return route.fulfill({ status: 200, json: sessions })
    }
    if (url.pathname === '/api/auth/sessions/other-handle/'
        && route.request().method() === 'DELETE') {
      if (!recentlyAuthenticated) return route.fulfill({ status: 403, json: {
        error: 'Confirm your identity to continue.',
        reauthentication_required: true,
        two_factor_required: true,
      } })
      otherActive = false
      return route.fulfill({ status: 204, body: '' })
    }
    return route.fallback()
  })
  await page.route('**/api/auth/reauthenticate/', async (route) => {
    reauthPayloads.push(route.request().postDataJSON())
    recentlyAuthenticated = true
    return route.fulfill({ status: 200, json: { authenticated: true, valid_for_seconds: 300 } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByTitle('Settings', { exact: true }).click()
  const panel = page.getByRole('heading', { name: 'Active sessions' }).locator('..')
  page.once('dialog', (dialog) => dialog.accept())
  await panel.getByRole('button', { name: 'Sign out', exact: true }).click()
  await expect(panel.getByText('this action needs a recent sign-in confirmation')).toBeVisible()
  await panel.getByLabel('Current password').fill('correct-password')
  await panel.getByLabel('2FA or recovery code').fill('123456')
  await panel.getByRole('button', { name: 'Confirm and continue' }).click()

  await expect(panel.getByText('Unknown browser')).toHaveCount(0)
  expect(reauthPayloads).toEqual([{ password: 'correct-password', code: '123456' }])
  await expectNoPageOverflow(page)
})

test('account export reauthenticates and starts a download without mobile overflow', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await page.addInitScript(() => {
    HTMLAnchorElement.prototype.click = function click() {
      window.__accountExportDownload = { href: this.href, download: this.download }
    }
  })
  await mockAPI(page)
  const reauthPayloads = []
  await page.route('**/api/auth/reauthenticate/', async (route) => {
    reauthPayloads.push(route.request().postDataJSON())
    await route.fulfill({ status: 200, json: { authenticated: true, valid_for_seconds: 300 } })
  })
  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByTitle('Settings', { exact: true }).click()
  const panel = page.getByRole('heading', { name: 'Export your data' }).locator('..')
  await panel.getByRole('button', { name: 'Prepare account export…' }).click()
  await panel.getByLabel('Current password').fill('correct-password')
  await panel.getByRole('button', { name: 'Verify and download' }).click()

  expect(reauthPayloads).toEqual([{ password: 'correct-password' }])
  await expect.poll(
    () => page.evaluate(() => window.__accountExportDownload),
  ).toEqual({
    href: 'http://127.0.0.1:5179/api/account/export/', download: '',
  })
  await expect(panel.getByLabel('Current password')).toHaveCount(0)
  await expectNoPageOverflow(page)
})

test('conversation export requires reauthentication and stays usable on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await page.addInitScript(() => {
    HTMLAnchorElement.prototype.click = function click() {
      window.__conversationExportDownload = { href: this.href, download: this.download }
    }
  })
  await mockAPI(page)
  const reauthPayloads = []
  await page.route('**/api/auth/reauthenticate/', async (route) => {
    const payload = route.request().postDataJSON()
    reauthPayloads.push(payload)
    if (!payload.code) {
      return route.fulfill({
        status: 401,
        json: { error: 'Two-factor code required.', two_factor_required: true },
      })
    }
    await route.fulfill({ status: 200, json: { authenticated: true, valid_for_seconds: 300 } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByRole('button', { name: /A useful conversation/ }).click()
  await page.getByRole('button', { name: 'Download conversation as Markdown' }).click()

  const dialog = page.getByRole('dialog', { name: 'Export conversation' })
  await expect(dialog).toBeVisible()
  await dialog.getByLabel('Current password').fill('correct-password')
  await dialog.getByRole('button', { name: 'Verify and download' }).click()
  await expect(dialog.getByLabel('2FA or recovery code')).toBeVisible()
  await page.screenshot({ path: 'test-results/conversation-export-320.png' })
  await dialog.getByLabel('2FA or recovery code').fill('aaaa1111-bbbb2222')
  await dialog.getByRole('button', { name: 'Verify and download' }).click()

  expect(reauthPayloads).toEqual([
    { password: 'correct-password' },
    { password: 'correct-password', code: 'aaaa1111-bbbb2222' },
  ])
  await expect.poll(
    () => page.evaluate(() => window.__conversationExportDownload),
  ).toEqual({
    href: 'http://127.0.0.1:5179/api/conversations/1/export/', download: '',
  })
  await expect(dialog).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Download conversation as Markdown' })).toBeFocused()
  await expectNoPageOverflow(page)
})

test('expired admin access requires responsive password and 2FA step-up', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await mockAPI(page)
  const payloads = []
  await page.route('**/api/auth/admin-reauthenticate/', async (route) => {
    payloads.push(route.request().postDataJSON())
    await route.fulfill({
      status: 200,
      json: { authenticated: true, valid_for_seconds: 300 },
    })
  })

  await page.goto('/?admin_reauth=1&next=%2Fadmin%2Fchat%2F')
  const dialog = page.getByRole('dialog', { name: 'Confirm admin access' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByLabel('Current password')).toBeFocused()
  await dialog.getByLabel('Current password').fill('correct-password')
  await dialog.getByLabel('2FA or recovery code').fill('aaaa1111-bbbb2222')
  await page.screenshot({ path: 'test-results/admin-reauth-320.png' })
  await expectNoPageOverflow(page)
  await dialog.getByRole('button', { name: 'Verify and open admin' }).click()

  await expect.poll(() => payloads).toEqual([{
    password: 'correct-password', code: 'aaaa1111-bbbb2222',
  }])
  await page.waitForURL('**/admin/chat/')
  await expect(dialog).toHaveCount(0)
})

test('admin step-up rejects an external return target and can be canceled', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await mockAPI(page)
  await page.goto('/?admin_reauth=1&next=https%3A%2F%2Fattacker.invalid%2F')

  const dialog = page.getByRole('dialog', { name: 'Confirm admin access' })
  await expect(dialog).toBeVisible()
  await dialog.getByRole('button', { name: 'Cancel' }).click()

  await expect(dialog).toHaveCount(0)
  await expect.poll(() => page.evaluate(() => window.location.pathname + window.location.search)).toBe('/')
  await expectNoPageOverflow(page)
})

test('scheduled account deletion can be created and canceled on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await mockAPI(page)
  let scheduled = false
  const mutations = []
  await page.route('**/api/account/deletion/', async (route) => {
    const method = route.request().method()
    if (method === 'GET') {
      return route.fulfill({ status: 200, json: {
        scheduled, requested_at: scheduled ? '2026-10-18T00:00:00Z' : null,
        execute_after: scheduled ? '2026-10-25T00:00:00Z' : null, grace_days: 7,
      } })
    }
    mutations.push({ method, payload: route.request().postDataJSON() })
    scheduled = method === 'POST'
    return route.fulfill({ status: method === 'POST' ? 201 : 200, json: {
      scheduled, requested_at: scheduled ? '2026-10-18T00:00:00Z' : null,
      execute_after: scheduled ? '2026-10-25T00:00:00Z' : null, grace_days: 7,
    } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByTitle('Settings', { exact: true }).click()
  const panel = page.getByRole('heading', { name: 'Danger zone' }).locator('..')
  await panel.getByRole('button', { name: 'Schedule deletion…' }).click()
  await panel.getByLabel('Scheduled deletion password').fill('correct-password')
  page.once('dialog', (dialog) => dialog.accept())
  await panel.getByRole('button', { name: 'Schedule account deletion' }).click()
  await expect(panel.getByText(/eligible for permanent deletion after/)).toBeVisible()

  await panel.getByRole('button', { name: 'Cancel scheduled deletion…' }).click()
  await panel.getByLabel('Scheduled deletion password').fill('correct-password')
  await panel.getByRole('button', { name: 'Keep my account' }).click()
  await expect(panel.getByText(/Start a 7-day grace period/)).toBeVisible()
  expect(mutations).toEqual([
    { method: 'POST', payload: { password: 'correct-password' } },
    { method: 'DELETE', payload: { password: 'correct-password' } },
  ])
  await expectNoPageOverflow(page)
})

async function expectNoPageOverflow(page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
}

for (const width of [320, 390, 768, 1440]) {
  test(`chat and settings fit ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 })
    await mockAPI(page)
    await page.goto('/')
    await expect(page.getByRole('textbox', { name: 'Message', exact: true })).toBeVisible()
    if (width <= 760) await page.getByRole('button', { name: 'Open conversations' }).click()
    await page.getByRole('button', { name: /A useful conversation/ }).click()
    await expect(page.getByText('Open image: tracker', { exact: true })).toBeVisible()
    await expect(page.locator('img[src*="tracker.invalid"]')).toHaveCount(0)
    await expect(page.getByText('blocked script', { exact: true })).toBeVisible()
    await expect(page.getByText('blocked script', { exact: true })).not.toHaveAttribute('href')
    await expect(page.getByText('Blocked image: inline tracker', { exact: true })).toBeVisible()
    await expect(page.locator('[href^="javascript:"], [href^="data:"]')).toHaveCount(0)
    expect(await page.evaluate(() => window.__markdownExecuted)).toBeUndefined()
    await expectNoPageOverflow(page)
    await page.screenshot({ path: `test-results/chat-${width}.png` })
    if (width <= 760) await page.getByRole('button', { name: 'Open conversations' }).click()
    await page.getByTitle('Settings', { exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Storage & files' })).toBeVisible()
    await expect(page.getByText('5.0 MB of 100 MB used')).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Saved chat data' })).toBeVisible()
    await expect(page.getByLabel('Conversation storage used')).toHaveAttribute('value', '1')
    await expect(page.getByLabel('Message storage used')).toHaveAttribute('value', '2')
    await expect(page.getByRole('heading', { name: "Today's AI usage" })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Export your data' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Privacy & data' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open the complete privacy notice' })).toHaveAttribute(
      'href', '/privacy/',
    )
    await expect(page.getByLabel('Daily chat requests used')).toHaveAttribute('value', '4')
    await expect(page.getByLabel('Daily generated images used')).toHaveAttribute('value', '1')
    await page.getByLabel('Color theme').selectOption('light')
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
    await expectNoPageOverflow(page)
    await page.screenshot({ path: `test-results/settings-${width}.png` })
    await page.getByRole('heading', { name: 'Danger zone' }).scrollIntoViewIfNeeded()
    await expect(page.getByRole('heading', { name: 'Danger zone' })).toBeInViewport()
    await expectNoPageOverflow(page)
  })

  test(`sign in fits ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 568 })
    await mockAPI(page, false)
    await page.goto('/')
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Privacy & data' })).toHaveAttribute('href', '/privacy/')
    await expectNoPageOverflow(page)
  })
}

test('mobile drawer closes with Escape and returns keyboard focus', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  await page.goto('/')
  const menu = page.getByRole('button', { name: 'Open conversations' })
  await menu.click()
  await expect(menu).toHaveAttribute('aria-expanded', 'true')
  await page.keyboard.press('Escape')
  await expect(menu).toHaveAttribute('aria-expanded', 'false')
  await expect(menu).toBeFocused()
})

test('conversation pin and archive controls stay clear and recoverable on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await mockAPI(page)
  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()

  const actions = page.getByRole('button', { name: 'Conversation actions' })
  await actions.click()
  await page.screenshot({ path: 'test-results/conversation-actions-320.png' })
  await page.getByRole('button', { name: 'Pin', exact: true }).click()
  await expect(page.getByTitle('Pinned')).toBeVisible()
  await expect(page.getByRole('status')).toContainText('pinned')

  await actions.click()
  await page.getByRole('button', { name: 'Archive', exact: true }).click()
  await expect(page.getByText('Conversation moved to Archived.')).toBeVisible()
  await expect(page.getByRole('button', { name: /^Archived 1$/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /A useful conversation/ })).toHaveCount(0)

  await page.getByRole('button', { name: /^Archived 1$/ }).click()
  await expect(page.getByRole('button', { name: /A useful conversation/ })).toBeVisible()
  await page.getByRole('button', { name: 'Conversation actions' }).click()
  await page.getByRole('button', { name: 'Restore', exact: true }).click()
  await expect(page.getByText('Conversation restored to Active.')).toBeVisible()
  await expect(page.getByRole('button', { name: /^Active 1$/ })).toBeVisible()
  await expectNoPageOverflow(page)
})

test('conversation history loads signed-cursor pages without mobile overflow', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await mockAPI(page)
  const conversations = Array.from({ length: 35 }, (_, index) => ({
    id: index + 10,
    title: `History item ${String(index + 1).padStart(2, '0')}`,
    model_id: 'test/model',
    message_count: index,
    is_pinned: false,
    archived_at: null,
    created_at: `2026-10-05T11:${String(index).padStart(2, '0')}:00Z`,
    updated_at: `2026-10-05T11:${String(index).padStart(2, '0')}:00Z`,
  }))
  await page.route('**/api/conversations/**', (route) => {
    const request = route.request()
    const url = new URL(request.url())
    if (url.pathname !== '/api/conversations/' || request.method() !== 'GET') {
      return route.fallback()
    }
    const secondPage = url.searchParams.get('cursor') === 'second-page'
    return route.fulfill({ status: 200, json: {
      results: secondPage ? conversations.slice(30) : conversations.slice(0, 30),
      counts: { active: 35, archived: 0 },
      next_cursor: secondPage ? null : 'second-page',
    } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await expect(page.locator('.convo-item')).toHaveCount(30)
  await expect(page.getByRole('button', { name: /^Active 35$/ })).toBeVisible()
  await page.getByRole('button', { name: 'Load more conversations' }).click()
  await expect(page.locator('.convo-item')).toHaveCount(35)
  await expect(page.getByRole('button', { name: 'Load more conversations' })).toHaveCount(0)
  await expectNoPageOverflow(page)
})

test('earlier messages prepend without losing the mobile history', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  const message = (id) => ({
    id,
    role: id % 2 ? 'user' : 'assistant',
    content: `History message ${id} ` + 'content '.repeat(30),
    attachments: [],
    created_at: `2026-10-05T10:0${id}:00Z`,
  })
  await page.route('**/api/conversations/1/**', (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (request.method() !== 'GET') return route.fallback()
    if (path === '/api/conversations/1/') {
      return route.fulfill({ status: 200, json: {
        id: 1, title: 'A useful conversation', model_id: 'test/model',
        is_pinned: false, archived_at: null,
        system_prompt: '', temperature: 0.7, max_tokens: 1024,
        messages: [message(5), message(6), message(7)],
        message_page: { count: 7, older_cursor: 'older-page' },
      } })
    }
    if (path === '/api/conversations/1/messages/') {
      return route.fulfill({ status: 200, json: {
        results: [message(2), message(3), message(4)],
        count: 7,
        older_cursor: 'oldest-page',
      } })
    }
    return route.fallback()
  })

  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByRole('button', { name: /A useful conversation/ }).click()
  await expect(page.locator('.msg')).toHaveCount(3)
  await page.getByRole('button', { name: /Load earlier messages/ }).click()
  await expect(page.locator('.msg')).toHaveCount(6)
  await expect(page.locator('.msg').first()).toContainText('History message 2')
  await expect(page.getByRole('button', { name: /6 of 7/ })).toBeVisible()
  await expectNoPageOverflow(page)
})

test('private file library loads attachment cursor pages on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  const files = Array.from({ length: 35 }, (_, index) => ({
    id: index + 100,
    kind: 'document',
    original_name: `private-${String(index + 1).padStart(2, '0')}.txt`,
    mime_type: 'text/plain',
    size: 1024,
    url: `/api/attachments/${index + 100}/download/`,
    has_text: true,
    deletable: false,
    created_at: `2026-10-05T09:${String(index).padStart(2, '0')}:00Z`,
  }))
  await page.route('**/api/attachments/**', (route) => {
    const request = route.request()
    const url = new URL(request.url())
    if (url.pathname !== '/api/attachments/' || request.method() !== 'GET') {
      return route.fallback()
    }
    if (url.searchParams.get('kind') === 'generated_image') {
      return route.fulfill({ status: 200, json: {
        results: [], count: 0, next_cursor: null,
      } })
    }
    const secondPage = url.searchParams.get('cursor') === 'files-page-2'
    return route.fulfill({ status: 200, json: {
      results: secondPage ? files.slice(30) : files.slice(0, 30),
      count: 35,
      next_cursor: secondPage ? null : 'files-page-2',
    } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByTitle('Settings', { exact: true }).click()
  await expect(page.locator('.library-row')).toHaveCount(30)
  await page.getByRole('button', { name: 'Load more files' }).click()
  await expect(page.locator('.library-row')).toHaveCount(35)
  await expect(page.getByRole('button', { name: 'Load more files' })).toHaveCount(0)
  await expectNoPageOverflow(page)
})

test('retired conversation model is explicit and recoverable on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await mockAPI(page, true, 'retired/model')
  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByRole('button', { name: /A useful conversation/ }).click()

  await expect(page.getByRole('alert')).toContainText('model is no longer available')
  await expect(page.getByLabel('Chat model')).toHaveValue('retired/model')
  await expect(page.getByLabel('Message')).toBeDisabled()
  await expectNoPageOverflow(page)

  await page.getByRole('button', { name: 'Use Test Vision' }).click()
  await expect(page.getByRole('alert')).toHaveCount(0)
  await expect(page.getByLabel('Chat model')).toHaveValue('test/model')
  await expect(page.getByLabel('Message')).toBeEnabled()
  await expectNoPageOverflow(page)
})

test('invite-only registration requires an invitation code', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 700 })
  await mockAPI(page, false, 'test/model', 'invite')
  await page.goto('/')
  await page.getByRole('button', { name: 'Create one' }).click()
  await expect(page.getByText('Create an invited account')).toBeVisible()
  await expect(page.getByLabel('Invitation code')).toBeVisible()
  await expectNoPageOverflow(page)
})

test('closed registration exposes no account creation control', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 568 })
  await mockAPI(page, false, 'test/model', 'closed')
  await page.goto('/')
  await expect(page.getByText('New account registration is currently closed.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Create one' })).toHaveCount(0)
  await expectNoPageOverflow(page)
})

test('model capabilities drive the mobile attachment picker', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await mockAPI(page)
  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByRole('button', { name: /A useful conversation/ }).click()

  await expect(page.getByText('Images · max 1')).toBeVisible()
  await expect(page.getByText('128K context')).toBeVisible()
  await expect(page.getByText('Probe 2.4s')).toBeVisible()
  await expect(page.getByText('Best for:', { exact: false })).toBeVisible()
  await page.getByRole('button', { name: 'Add attachments' }).click()
  await expect(page.getByRole('button', { name: 'Add images' })).toBeEnabled()
  await expect(page.getByRole('button', { name: 'Add documents' })).toBeEnabled()
  await page.screenshot({ path: 'test-results/attachment-picker-320.png' })

  await page.getByLabel('Chat model').selectOption('text/model')
  await expect(page.getByText('No image input')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Add images' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Add documents' })).toBeEnabled()
  await expectNoPageOverflow(page)
})

test('switching models makes incompatible pending images explicit and recoverable', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByRole('button', { name: /A useful conversation/ }).click()
  await page.getByRole('button', { name: 'Add attachments' }).click()
  await page.getByLabel('Choose images').setInputFiles({
    name: 'diagram.png',
    mimeType: 'image/png',
    buffer: Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'),
  })
  await expect(page.getByAltText('diagram.png')).toBeVisible()

  await page.getByLabel('Chat model').selectOption('text/model')
  const warning = page.getByRole('alert')
  await expect(warning).toContainText('is not compatible')
  await expect(page.getByTitle('Send')).toBeDisabled()
  await page.getByRole('button', { name: 'Remove incompatible' }).click()
  await expect(warning).toHaveCount(0)
  await expect(page.getByAltText('diagram.png')).toHaveCount(0)
  await expectNoPageOverflow(page)
})

test('a pending file can be excluded without deleting it or blocking the selected model', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  await page.goto('/')
  await page.getByRole('button', { name: 'Add attachments' }).click()
  await page.getByLabel('Choose images').setInputFiles({
    name: 'diagram.png',
    mimeType: 'image/png',
    buffer: Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'),
  })
  await expect(page.getByAltText('diagram.png')).toBeVisible()

  await page.getByLabel('Chat model').selectOption('text/model')
  await expect(page.getByRole('alert')).toContainText('is not compatible')
  await page.getByRole('checkbox', { name: 'Include diagram.png in next message' }).uncheck()
  await expect(page.getByRole('alert')).toHaveCount(0)
  await expect(page.getByAltText('diagram.png')).toBeVisible()
  await page.getByRole('textbox', { name: 'Message', exact: true }).fill('Send without the excluded image')
  await expect(page.getByTitle('Send')).toBeEnabled()
  await expect(page.getByText('0 selected', { exact: false })).toBeVisible()
  await expectNoPageOverflow(page)
})

test('document preview renders extracted content as inert text and restores focus', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  await page.route('**/api/attachments/upload/', (route) => route.fulfill({ status: 201, json: {
    id: 910, kind: 'document', original_name: 'private.txt', mime_type: 'text/plain',
    size: 58, url: '/api/attachments/910/download/', has_text: true, deletable: true,
    deduplicated: false,
  } }))
  await page.goto('/')
  await page.getByLabel('Choose documents').setInputFiles({
    name: 'private.txt', mimeType: 'text/plain', buffer: Buffer.from('private text'),
  })

  const trigger = page.getByRole('button', { name: 'Preview text' })
  await trigger.click()
  const dialog = page.getByRole('dialog', { name: 'Extracted text preview' })
  await expect(dialog).toBeVisible()
  await expect(dialog.locator('pre')).toContainText('<script>window.__previewExecuted = true</script>')
  await expect(dialog.locator('script')).toHaveCount(0)
  expect(await page.evaluate(() => window.__previewExecuted)).toBeUndefined()
  await expectNoPageOverflow(page)
  await page.keyboard.press('Escape')
  await expect(dialog).toHaveCount(0)
  await expect(trigger).toBeFocused()
})

test('deduplicated uploads reuse one pending tile and explain the result', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  let attempts = 0
  await page.route('**/api/attachments/upload/', (route) => {
    attempts += 1
    return route.fulfill({ status: attempts === 1 ? 201 : 200, json: {
      id: 910, kind: 'document', original_name: 'notes.txt', mime_type: 'text/plain',
      size: 10, url: '/api/attachments/910/download/', has_text: true, deletable: true,
      deduplicated: attempts > 1,
    } })
  })
  await page.goto('/')
  const input = page.getByLabel('Choose documents')
  const file = { name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('same bytes') }
  await input.setInputFiles(file)
  await expect(page.locator('.att-tile.doc')).toHaveCount(1)
  await input.setInputFiles(file)

  await expect(page.locator('.att-tile.doc')).toHaveCount(1)
  await expect(page.getByRole('status')).toContainText('existing private copy was reused')
  expect(attempts).toBe(2)
  await expectNoPageOverflow(page)
})

test('model explorer searches, favorites, compares, and persists safely on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await mockAPI(page)
  await page.goto('/')
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByRole('button', { name: /A useful conversation/ }).click()

  const trigger = page.getByRole('button', { name: 'Open model explorer' })
  await trigger.click()
  const dialog = page.getByRole('dialog', { name: 'Choose a model' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('2 available', { exact: false })).toBeVisible()
  const search = page.getByPlaceholder('Search name, vendor, capability…')
  await expect(search).toBeFocused()

  await dialog.getByLabel('Sort models').selectOption('fastest')
  await expect(dialog.locator('.model-card-title strong').first()).toHaveText('Text Only')
  await expect(dialog.getByText('0.9s probe').first()).toBeVisible()
  await expect(dialog.getByText('Probe latency is one synthetic 1-token availability check')).toBeVisible()

  await dialog.getByRole('button', { name: 'Add Text Only to favorites' }).click()
  await search.fill('Text Only')
  await expect(dialog.getByRole('button', { name: 'Use Text Only' })).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Use Test Vision' })).toHaveCount(0)
  await dialog.getByRole('checkbox', { name: 'Compare Text Only' }).check()
  await search.clear()
  await dialog.getByRole('checkbox', { name: 'Compare Test Vision' }).check()
  await expect(dialog.getByText('2/3 selected')).toBeVisible()
  await page.screenshot({ path: 'test-results/model-explorer-320.png' })
  await expectNoPageOverflow(page)

  await page.keyboard.press('Escape')
  await expect(dialog).toHaveCount(0)
  await expect(trigger).toBeFocused()
  await trigger.click()
  await dialog.getByRole('button', { name: '★ Favorites' }).click()
  await expect(dialog.getByRole('button', { name: 'Use Text Only' })).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Use Test Vision' })).toHaveCount(0)
  await dialog.getByRole('button', { name: 'Use Text Only' }).click()
  await expect(page.getByLabel('Chat model')).toHaveValue('text/model')

  const stored = await page.evaluate(() => localStorage.getItem('aichat-model-preferences-v1'))
  expect(stored).toContain('text/model')
  expect(stored).not.toContain('A useful conversation')
})

test('model explorer ignores malformed local preferences', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.addInitScript(() => {
    localStorage.setItem('aichat-model-preferences-v1', '{not-json')
  })
  await mockAPI(page)
  await page.goto('/')
  await page.getByRole('button', { name: 'Open model explorer' }).click()
  const dialog = page.getByRole('dialog', { name: 'Choose a model' })
  await expect(dialog.getByRole('button', { name: 'Use Test Vision' })).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Use Text Only' })).toBeVisible()
  await expectNoPageOverflow(page)
})

test('degraded model availability is explicit without disabling last verified models', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 })
  await mockAPI(page, true, 'test/model', 'open', {
    state: 'degraded', checked_at: '2026-10-06T00:19:57Z', inconclusive_models: 1,
    unverified_models: 1, catalog_models: 3, available_models: 2, unavailable_models: 1,
  })
  await page.goto('/')

  await expect(page.getByRole('status')).toContainText('1 NVIDIA availability check was inconclusive')
  await expect(page.getByRole('status')).toContainText('1 new model is disabled pending verification')
  await expect(page.getByRole('status')).toContainText('2 of 3 catalog models are currently available')
  await expect(page.getByLabel('Chat model')).toBeEnabled()
  await page.getByRole('button', { name: 'Open model explorer' }).click()
  await expect(page.getByRole('dialog')).toContainText('last verified availability was retained')
  await expectNoPageOverflow(page)
})

test('verified availability explains models hidden by the latest probe', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page, true, 'test/model', 'open', {
    state: 'verified', checked_at: '2026-10-06T00:19:57Z', inconclusive_models: 0,
    unverified_models: 0, catalog_models: 3, available_models: 2, unavailable_models: 1,
  })
  await page.goto('/')

  await expect(page.getByRole('status')).toContainText('2 of 3 catalog models are currently available')
  await expect(page.getByRole('status')).toContainText('1 model is temporarily hidden')
  await page.getByRole('button', { name: 'Open model explorer' }).click()
  await expect(page.getByRole('dialog')).toContainText('2 of 3 available')
  await expectNoPageOverflow(page)
})

test('model comparison remains usable on desktop', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await mockAPI(page)
  await page.goto('/')
  await page.getByRole('button', { name: 'Open model explorer' }).click()
  const dialog = page.getByRole('dialog', { name: 'Choose a model' })
  await dialog.getByRole('checkbox', { name: 'Compare Test Vision' }).check()
  await dialog.getByRole('checkbox', { name: 'Compare Text Only' }).check()
  await expect(dialog.getByText('2/3 selected')).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Use model' })).toHaveCount(1)
  await expectNoPageOverflow(page)
  await page.screenshot({ path: 'test-results/model-explorer-1440.png' })
})

test('drag and drop attaches a capability-compatible image', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  await page.goto('/')
  const composer = page.locator('.composer-wrap')
  await composer.evaluate((element) => {
    const transfer = new DataTransfer()
    transfer.items.add(new File(
      [new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])],
      'dropped.png',
      { type: 'image/png' },
    ))
    window.__attachmentTransfer = transfer
    element.dispatchEvent(new DragEvent('dragenter', {
      bubbles: true, cancelable: true, dataTransfer: transfer,
    }))
  })
  await expect(page.getByText('Drop to attach')).toBeVisible()
  await composer.evaluate((element) => {
    element.dispatchEvent(new DragEvent('drop', {
      bubbles: true, cancelable: true, dataTransfer: window.__attachmentTransfer,
    }))
    delete window.__attachmentTransfer
  })
  await expect(page.getByAltText('diagram.png')).toBeVisible()
  await expect(page.getByText('Drop to attach')).toHaveCount(0)
  await expectNoPageOverflow(page)
})

test('pasting an image respects the selected model capability', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  await page.goto('/')
  await page.getByLabel('Chat model').selectOption('text/model')
  await page.getByLabel('Message').evaluate((element) => {
    const transfer = new DataTransfer()
    transfer.items.add(new File(
      [new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])],
      'pasted.png',
      { type: 'image/png' },
    ))
    element.dispatchEvent(new ClipboardEvent('paste', {
      bubbles: true, cancelable: true, clipboardData: transfer,
    }))
  })
  await expect(page.getByText(".png isn't supported here.")).toBeVisible()
  await expect(page.getByAltText('diagram.png')).toHaveCount(0)
})

test('failed upload is retryable without choosing the file again', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  let attempts = 0
  await page.route('**/api/attachments/upload/', (route) => {
    attempts += 1
    if (attempts === 1) {
      return route.fulfill({ status: 503, json: { error: 'Temporary upload failure.' } })
    }
    return route.fulfill({ status: 201, json: {
      id: 901, kind: 'image', original_name: 'retry.png', mime_type: 'image/png',
      size: 68, url: '/api/attachments/901/download/', has_text: false, deletable: true,
    } })
  })
  await page.goto('/')
  await page.getByRole('button', { name: 'Add attachments' }).click()
  await page.getByLabel('Choose images').setInputFiles({
    name: 'retry.png',
    mimeType: 'image/png',
    buffer: Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'),
  })
  await expect(page.getByText('Temporary upload failure.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible()
  await page.screenshot({ path: 'test-results/upload-retry-390.png' })
  await page.getByRole('button', { name: 'Retry' }).click()
  await expect(page.getByAltText('retry.png')).toBeVisible()
  expect(attempts).toBe(2)
  await expectNoPageOverflow(page)
})

test('in-flight upload can be canceled without becoming pending', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  let uploadedAttemptId = null
  let canceledAttemptId = null
  await page.route('**/api/attachments/upload/', async (route) => {
    uploadedAttemptId = route.request().postData()?.match(
      /name="upload_attempt_id"\r\n\r\n([0-9a-f-]{36})/,
    )?.[1]
    await new Promise((resolve) => setTimeout(resolve, 800))
    try {
      await route.fulfill({ status: 201, json: {
        id: 902, kind: 'image', original_name: 'slow.png', mime_type: 'image/png',
        size: 68, url: '/api/attachments/902/download/', has_text: false, deletable: true,
      } })
    } catch { /* the browser canceled the intercepted request */ }
  })
  await page.route('**/api/attachments/upload/*/', async (route) => {
    canceledAttemptId = new URL(route.request().url()).pathname.split('/').at(-2)
    await route.fulfill({ status: 204, body: '' })
  })
  await page.goto('/')
  await page.getByRole('button', { name: 'Add attachments' }).click()
  await page.getByLabel('Choose images').setInputFiles({
    name: 'slow.png',
    mimeType: 'image/png',
    buffer: Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'),
  })
  await page.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByText('Upload canceled')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible()
  await expect(page.getByAltText('slow.png')).toHaveCount(0)
  await expect.poll(() => uploadedAttemptId).toMatch(/^[0-9a-f-]{36}$/)
  await expect.poll(() => canceledAttemptId).toBe(uploadedAttemptId)
})

test('logout clears pending attachment previews from browser memory', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockAPI(page)
  await page.goto('/')
  await page.getByRole('button', { name: 'Add attachments' }).click()
  await page.getByLabel('Choose images').setInputFiles({
    name: 'private.png',
    mimeType: 'image/png',
    buffer: Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'),
  })
  await expect(page.getByAltText('diagram.png')).toBeVisible()
  await page.getByRole('button', { name: 'Open conversations' }).click()
  await page.getByTitle('Sign out').click()
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible()
  await expect(page.getByAltText('diagram.png')).toHaveCount(0)
})
