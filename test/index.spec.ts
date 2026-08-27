// test/index.spec.ts
import { SELF, env } from 'cloudflare:test';
import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('GET /', () => {
	it('responds with no-op (Hello)', async () => {
		const response = await SELF.fetch('https://example.com');
		expect(await response.text()).toMatchInlineSnapshot(`"Hello 👋"`);
	});
});

describe('GET /auth', () => {
	it('responds with redirected location', async () => {
		const response = await SELF.fetch('https://example.com/auth?provider=github');
		expect(response.status).toBe(200);
		expect(response.url).toEqual(
			expect.stringContaining(
				'https://github.com/login/oauth/authorize?response_type=code&client_id=undefined&redirect_uri=https://example.com/callback?provider=github&scope=repo,user&state='
			)
		);
	});
});

describe('GET /callback', () => {
	it('responds with html page w/ JS messaging script', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () =>
				new Response(JSON.stringify({ access_token: 'some-access-token' }), {
					headers: { 'Content-Type': 'application/json' },
				})
			)
		);

		const response = await SELF.fetch(
			'https://example.com/callback?provider=github&code=some-authorization-code'
		);
		expect(response.status).toBe(200);
		const responseBody = await response.text();
		expect(responseBody).toEqual(expect.stringContaining('window.opener.postMessage("authorizing:github", "*");'));
	});
});

describe('POST /upload', () => {
	it('rejects a request with no token', async () => {
		const response = await SELF.fetch('https://example.com/upload', { method: 'POST', body: 'video bytes' });
		expect(response.status).toBe(401);
	});

	it('rejects a token without push access to the repo', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => new Response(JSON.stringify({ permissions: { push: false } }), { status: 200 }))
		);

		const response = await SELF.fetch('https://example.com/upload', {
			method: 'POST',
			headers: { Authorization: 'token some-token' },
			body: 'video bytes',
		});
		expect(response.status).toBe(403);
	});

	it('rejects a token GitHub itself refuses (expired/invalid)', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => new Response('Bad credentials', { status: 401 }))
		);

		const response = await SELF.fetch('https://example.com/upload', {
			method: 'POST',
			headers: { Authorization: 'token some-token' },
			body: 'video bytes',
		});
		expect(response.status).toBe(403);
	});

	it('stores the file in R2 and returns its key for a token with push access', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => new Response(JSON.stringify({ permissions: { push: true } }), { status: 200 }))
		);

		const response = await SELF.fetch('https://example.com/upload', {
			method: 'POST',
			headers: { Authorization: 'token some-token', 'X-Filename': 'hero.mp4' },
			body: 'video bytes',
		});
		expect(response.status).toBe(200);

		const { key } = (await response.json()) as { key: string };
		expect(key).toMatch(/\.mp4$/);

		const stored = await env.RAW_UPLOADS_BUCKET.get(key);
		expect(stored).not.toBeNull();
		expect(await stored?.text()).toBe('video bytes');
	});
});
