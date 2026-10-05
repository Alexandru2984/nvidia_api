import { test, expect } from '@playwright/test'

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
    const data = {
      '/api/auth/me/': {
        username: signedIn ? 'alice' : null,
        registration_mode: registrationMode,
      },
      '/api/models/': { models: [{ id: 'test/model', name: 'Test model', vendor: 'Test', vision: true }], default: 'test/model' },
      '/api/conversations/': [conversation],
      '/api/conversations/1/': conversation,
      '/api/images/models/': { models: [], default: '' },
      '/api/attachments/': [],
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

  await page.getByRole('button', { name: 'Use Test model' }).click()
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
