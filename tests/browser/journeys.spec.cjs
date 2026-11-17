const {test: base, expect} = require('@playwright/test');

const test = base.extend({
  browserFailures: [async ({context}, use) => {
    const errors = [];
    context.on('page', page => page.on('pageerror', error => errors.push(error.message)));
    context.on('response', response => {
      if (response.status() >= 500) errors.push(`${response.status()} ${new URL(response.url()).pathname}`);
    });
    await use();
    expect(errors, 'Unhandled browser errors or server failures').toEqual([]);
  }, {auto: true}],
});

const guestRoot = '/g/page-a/grant_aaaaaaaaaaaaaaaa/';
const invitation = guestRoot + '?bootstrap=bootstrap-secret-a-1234567890';

// Browser contexts are fresh for each test. Each journey owns different page
// data; retries are disabled so a second attempt cannot hide state-dependent bugs.
test.beforeEach(async ({context}) => {
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    return url.hostname === '127.0.0.1' ? route.continue() : route.abort();
  });
});

test('owner creates, edits and previews a page inside an ingress iframe', async ({page, request}) => {
  const escapedRequests = [];
  page.on('request', req => {
    const path = new URL(req.url()).pathname;
    if (path.startsWith('/api/admin/') || path.startsWith('/static/')) escapedRequests.push(path);
  });
  expect((await request.get('/api/admin/pages')).status()).toBe(401);
  await page.goto('/ha');
  const app = page.frameLocator('iframe[title="Access Pages"]');
  await app.getByRole('button', {name: '+ New page', exact: true}).click();
  await app.getByLabel('Page name', {exact: true}).fill('Browser owner');
  await app.locator('#open-picker').click();
  await app.locator('#picker-search').fill('Other light');
  await app.getByRole('checkbox', {name: /Other light/}).check();
  await app.getByRole('button', {name: 'Apply selections', exact: true}).click();
  await app.locator('#save').click();
  await expect(app.locator('#status')).toHaveText('Page saved.');
  await app.getByLabel('Description shown to the guest').fill('Saved through real ingress');
  await app.locator('#save').click();
  await expect(app.locator('#status')).toHaveText('Page saved.');
  await page.reload();
  await app.locator('.page-card').filter({hasText: 'Browser owner'}).getByRole('button', {name: 'Edit', exact: true}).click();
  await expect(app.getByLabel('Description shown to the guest')).toHaveValue('Saved through real ingress');
  await app.locator('#preview').click();
  await expect(app.getByRole('heading', {name: 'Browser owner', exact: true})).toBeVisible();
  await expect(app.getByText('Saved through real ingress', {exact: true})).toBeVisible();
  const count = (await (await request.get('/__calls')).json()).length;
  await app.getByRole('button', {name: 'Turn on', exact: true}).click();
  await expect.poll(async () => (await (await request.get('/__calls')).json()).length).toBe(count + 1);
  await app.getByRole('button', {name: '← Back to Access Pages', exact: true}).click();
  await expect(app.getByRole('heading', {name: 'Pages', exact: true})).toBeVisible();
  expect(escapedRequests).toEqual([]);
});

test('mobile guest can use only saved controls and loses access after owner revocation', async ({page, context, request}) => {
  await page.setViewportSize({width: 390, height: 844});
  await page.goto(invitation);
  await expect(page).toHaveURL(new RegExp(guestRoot + '$'));
  await expect(page.getByRole('heading', {name: 'Page A', exact: true})).toBeVisible();
  await expect(page.getByRole('button', {name: 'Turn off', exact: true})).toHaveCount(0);
  await expect(page.getByRole('button', {name: 'Turn on', exact: true})).toBeVisible();
  const cookie = (await context.cookies()).find(cookie => cookie.name === 'access_pages_guest');
  expect(cookie).toMatchObject({secure: true, httpOnly: true, sameSite: 'Lax', path: guestRoot});
  const count = (await (await request.get('/__calls')).json()).length;
  await page.getByRole('button', {name: 'Turn on', exact: true}).click();
  await expect.poll(async () => (await (await request.get('/__calls')).json()).length).toBe(count + 1);

  // Submit from the browser with its real session cookie. The backend must
  // reject a control absent from saved policy, even if the caller invents it.
  const denied = await page.evaluate(async root => (await fetch(root + 'api/access/page-a/garden/turn_off', {
    method: 'POST', headers: {'Content-Type': 'application/json', 'X-Guest-Request': '1'}, body: '{}',
  })).status, guestRoot);
  expect(denied).toBe(404);
  expect((await (await request.get('/__calls')).json()).length).toBe(count + 1);

  const owner = await context.newPage();
  await owner.goto('/ha');
  const app = owner.frameLocator('iframe[title="Access Pages"]');
  await app.locator('.page-card').filter({hasText: 'Page A'}).getByRole('button', {name: 'Guests', exact: true}).click();
  await app.getByRole('button', {name: 'Revoke this link', exact: true}).click();
  await app.locator('#confirm-dialog').getByRole('button', {name: 'Cancel', exact: true}).click();
  await expect(app.getByRole('button', {name: 'Revoke this link', exact: true})).toBeVisible();
  await app.getByRole('button', {name: 'Revoke this link', exact: true}).click();
  await app.locator('#accept-confirm').click();
  await expect(app.getByRole('button', {name: 'Revoke this link', exact: true})).toHaveCount(0);
  await page.bringToFront();
  await expect(page.locator('#status')).toContainText('expired or been revoked', {timeout: 15_000});
  await expect(page.locator('#resources')).toBeEmpty();
  const revoked = await page.evaluate(async root => (await fetch(root + 'api/access/page-a/garden/turn_on', {
    method: 'POST', headers: {'Content-Type': 'application/json', 'X-Guest-Request': '1'}, body: '{}',
  })).status, guestRoot);
  expect(revoked).toBe(401);
  expect((await (await request.get('/__calls')).json()).length).toBe(count + 1);
});
