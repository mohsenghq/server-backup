import { expect, test, type Page } from '@playwright/test'

// Credentials for the admin the harness seeds into the test catalog.
const ADMIN = { username: 'admin', password: 'admin-password-123' }

// Locators scoped to the hosts section: the advanced-mode policy editor uses
// identical placeholders, so page-wide lookups would be ambiguous.
function hostSection(page: Page) {
  return page.getByRole('heading', { name: 'Hosts', level: 2 }).locator('..').locator('..')
}

// The backup form sits between the hosts table and the advanced section.
function backupSection(page: Page) {
  return page.getByRole('heading', { name: 'Run backup', level: 2 }).locator('..')
}

test('login → add host → run backup → live progress', async ({ page }) => {
  // 1. Login screen → dashboard.
  await page.goto('/')
  await page.getByPlaceholder('username').fill(ADMIN.username)
  await page.getByPlaceholder('password').fill(ADMIN.password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible({ timeout: 15_000 })

  // 2. Add-host wizard.
  const hosts = hostSection(page)
  const hostName = `e2e-host-${Date.now()}`
  await hosts.getByRole('button', { name: 'Add host' }).click()
  await hosts.getByPlaceholder('name').fill(hostName)
  await hosts.getByPlaceholder('address').fill('127.0.0.1')
  await hosts.getByPlaceholder('port').fill(process.env.AEGIS_E2E_SSH_PORT ?? '22')
  await hosts.getByPlaceholder('ssh user').fill(process.env.AEGIS_E2E_SSH_USER ?? 'aegis-test')
  if (process.env.AEGIS_E2E_SSH_KEY) {
    await hosts
      .getByPlaceholder(/OpenSSH private key/)
      .fill(process.env.AEGIS_E2E_SSH_KEY.replace(/\\n/g, '\n'))
  }
  await hosts.getByRole('button', { name: 'Add', exact: true }).click()

  // The new host appears in the table.
  const row = page.getByRole('row', { name: new RegExp(hostName) })
  await expect(row).toBeVisible({ timeout: 10_000 })

  // 3. Run a backup against it.
  const backup = backupSection(page)
  await backup.getByRole('combobox').selectOption({ label: hostName })
  await backup
    .getByPlaceholder('repo path or sftp://…')
    .fill(process.env.AEGIS_E2E_REPO ?? '/tmp/aegis-e2e-repo')
  await backup
    .getByPlaceholder(/absolute remote paths/)
    .fill(process.env.AEGIS_E2E_PATHS ?? '/srv/backup-me')
  await backup.getByRole('button', { name: 'Run backup' }).click()

  // 4. Either the live WS banner or the inline "snapshot created" note
  //    confirms the job ran end-to-end.
  await expect(
    page.getByText(/snapshot [0-9a-f-]+ created|Job (started|completed)/),
  ).toBeVisible({ timeout: 60_000 })

  // 5. The jobs table shows the run.
  await expect(page.getByRole('cell', { name: hostName })).toBeVisible({
    timeout: 15_000,
  })
})

test('bad credentials are rejected', async ({ page }) => {
  await page.goto('/')
  await page.getByPlaceholder('username').fill('admin')
  await page.getByPlaceholder('password').fill('wrong-password')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText(/invalid credentials|login failed/i)).toBeVisible()
})
