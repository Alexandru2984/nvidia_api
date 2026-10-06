import { test, expect } from '@playwright/test'
import { Buffer } from 'node:buffer'

async function mockAPI(
  page, signedIn = true, conversationModel = 'test/model', registrationMode = 'open',
) {
  await page.route('https://analytics.micutu.com/**', (route) => route.abort())
  const conversation = {
    id: 1, title: 'A useful conversation', model_id: conversationModel, message_count: 2,
    messages: [
      { id: 1, role: 'user', content: 'Explain this code', attachments: [] },
      { id: 2, role: 'assistant', content: '```js\nconst value = 42\n```\n\n' + 'longword'.repeat(70)
        + '\n\n![tracker](https://tracker.invalid/pixel)\n\n| A | B |\n|---|---|\n| first | second |', attachments: [] },
    ],
  }
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/conversations/1/' && route.request().method() === 'PATCH') {
      const patch = route.request().postDataJSON()
      return route.fulfill({ status: 200, json: { ...conversation, ...patch } })
    }
    if (path === '/api/attachments/upload/' && route.request().method() === 'POST') {
      return route.fulfill({ status: 201, json: {
        id: 900, kind: 'image', original_name: 'diagram.png', mime_type: 'image/png',
        size: 68, url: '/api/attachments/900/download/', has_text: false, deletable: true,
        deduplicated: false,
      } })
    }
    if (/^\/api\/attachments\/(900|910)\/$/.test(path) && route.request().method() === 'DELETE') {
      return route.fulfill({ status: 204, body: '' })
    }
    const data = {
      '/api/auth/me/': {
        username: signedIn ? 'alice' : null,
        registration_mode: registrationMode,
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
          },
        ],
        default: 'test/model',
        availability_checked_at: '2026-10-06T00:19:57Z',
        attachment_limits: {
          max_files_per_message: 8, max_file_bytes: 10485760,
          max_bytes_per_message: 20971520,
        },
      },
      '/api/conversations/': [conversation],
      '/api/conversations/1/': conversation,
      '/api/images/models/': { models: [], default: '' },
      '/api/attachments/': [],
      '/api/attachments/910/preview/': {
        text: 'Safe text <script>window.__previewExecuted = true</script>',
        characters: 58,
        truncated: false,
      },
      '/api/account/usage/': {
        storage_bytes: 5242880, storage_limit_bytes: 104857600, attachments: 0, conversations: 1, messages: 2,
        ai_today: {
          date: '2026-10-05', chat_requests: 4, chat_limit: 100, image_requests: 1, image_limit: 10,
          prompt_characters: 420, resets_at: '2026-10-06T00:00:00Z', enabled: true,
        },
      },
      '/api/auth/2fa/status/': { enabled: false, recovery_codes_remaining: 0 },
      '/api/auth/sessions/': [{ id: 'opaque-handle', current: true, ua: 'Browser', ip: '198.51.100.1', expires_at: '2026-11-01T00:00:00Z' }],
    }[path]
    return route.fulfill({ status: data ? 200 : 404, json: data || { error: 'Unexpected mock request' } })
  })
}

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
    await expectNoPageOverflow(page)
    await page.screenshot({ path: `test-results/chat-${width}.png` })
    if (width <= 760) await page.getByRole('button', { name: 'Open conversations' }).click()
    await page.getByTitle('Settings', { exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Storage & files' })).toBeVisible()
    await expect(page.getByText('5.0 MB of 100 MB used')).toBeVisible()
    await expect(page.getByRole('heading', { name: "Today's AI usage" })).toBeVisible()
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
  await page.route('**/api/attachments/upload/', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 800))
    try {
      await route.fulfill({ status: 201, json: {
        id: 902, kind: 'image', original_name: 'slow.png', mime_type: 'image/png',
        size: 68, url: '/api/attachments/902/download/', has_text: false, deletable: true,
      } })
    } catch { /* the browser canceled the intercepted request */ }
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
