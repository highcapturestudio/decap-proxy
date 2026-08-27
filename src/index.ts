import { OAuthClient } from './oauth';

interface Env {
	GITHUB_OAUTH_ID: string;
	GITHUB_OAUTH_SECRET: string;
  GITHUB_REPO_PRIVATE?: string;
	GITHUB_REPO: string;
	RAW_UPLOADS_BUCKET: R2Bucket;
}

function randomHex(bytes: number): string {
	const buf = new Uint8Array(bytes);
	crypto.getRandomValues(buf);
	return Array.from(buf)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

const createOAuth = (env: Env) => {
	return new OAuthClient({
		id: env.GITHUB_OAUTH_ID,
		secret: env.GITHUB_OAUTH_SECRET,
		target: {
			tokenHost: 'https://github.com',
			tokenPath: '/login/oauth/access_token',
			authorizePath: '/login/oauth/authorize',
		},
	});
};

const handleAuth = async (url: URL, env: Env) => {
	const provider = url.searchParams.get('provider');
	if (provider !== 'github') {
		return new Response('Invalid provider', { status: 400 });
	}

  const repoIsPrivate = env.GITHUB_REPO_PRIVATE != undefined && env.GITHUB_REPO_PRIVATE !== '0';
  const repoScope = repoIsPrivate ? 'repo,user' : 'public_repo,user';

	const oauth2 = createOAuth(env);
	const authorizationUri = oauth2.authorizeURL({
		redirect_uri: `https://${url.hostname}/callback?provider=github`,
		scope: repoScope,
		state: randomHex(4), // 4 bytes -> 8 hex chars
	});

	return new Response(null, { headers: { location: authorizationUri }, status: 301 });
};

const callbackScriptResponse = (status: string, token: string) => {
	return new Response(
		`
<html>
<head>
  <script>
    const receiveMessage = (message) => {
      window.opener.postMessage(
        'authorization:github:${status}:${JSON.stringify({ token })}',
        '*'
      );
      window.removeEventListener("message", receiveMessage, false);
    }
    window.addEventListener("message", receiveMessage, false);
    window.opener.postMessage("authorizing:github", "*");
  </script>
  <body>
    <p>Authorizing Decap...</p>
  </body>
</head>
</html>
`,
		{ headers: { 'Content-Type': 'text/html' } }
	);
};

const handleCallback = async (url: URL, env: Env) => {
	const provider = url.searchParams.get('provider');
	if (provider !== 'github') {
		return new Response('Invalid provider', { status: 400 });
	}

	const code = url.searchParams.get('code');
	if (!code) {
		return new Response('Missing code', { status: 400 });
	}

	const oauth2 = createOAuth(env);
	const accessToken = await oauth2.getToken({
		code,
		redirect_uri: `https://${url.hostname}/callback?provider=github`,
	});
	return callbackScriptResponse('success', accessToken);
};

// No allow-listed origin here: the CMS admin panel can be reached from
// production, Cloudflare Pages preview deploys, or localhost during
// development, and none of those are fixed ahead of time. CORS is a
// browser-only courtesy anyway — it doesn't gate anything a direct curl
// request couldn't already do — the real gate is the GitHub permission
// check inside handleUpload below.
const UPLOAD_CORS_HEADERS = {
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'POST, OPTIONS',
	// Content-Type is required here even though the Worker itself never reads
	// it: fetch() auto-sets it from the File's own MIME type when a File is
	// passed as the body (see admin/video-upload-widget.js), which makes it
	// part of the browser's CORS preflight request whether we want it or not.
	'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Filename',
};

// Accepts a raw video file from the (already GitHub-logged-in) Decap CMS
// admin panel and stores it in the private RAW_UPLOADS_BUCKET, bypassing
// GitHub entirely — see the R2 migration this endpoint exists for. Every
// request is checked fresh against GitHub's own API; nothing about
// "who's allowed" is cached or trusted from a prior request.
const handleUpload = async (request: Request, env: Env) => {
	if (request.method === 'OPTIONS') {
		return new Response(null, { headers: UPLOAD_CORS_HEADERS });
	}

	if (request.method !== 'POST') {
		return new Response('Method not allowed', { status: 405, headers: UPLOAD_CORS_HEADERS });
	}

	const token = request.headers.get('Authorization');
	if (!token) {
		return new Response('Missing token', { status: 401, headers: UPLOAD_CORS_HEADERS });
	}

	// Live permission check, every time: does the account behind this token
	// currently have push access to the site's repo? A token that merely
	// proves "a real GitHub account authorized this app" (which anyone can
	// get) is not sufficient on its own — see the repo's config.yml backend
	// and this project's own auth writeup for why these are different things.
	const repoCheck = await fetch(`https://api.github.com/repos/${env.GITHUB_REPO}`, {
		headers: {
			Authorization: token,
			'User-Agent': 'highcapturestudio-auth-worker',
		},
	});

	if (!repoCheck.ok) {
		return new Response('Not authorized', { status: 403, headers: UPLOAD_CORS_HEADERS });
	}

	const repoInfo = (await repoCheck.json()) as { permissions?: { push?: boolean } };
	if (!repoInfo.permissions?.push) {
		return new Response('Not authorized', { status: 403, headers: UPLOAD_CORS_HEADERS });
	}

	if (!request.body) {
		return new Response('Missing file', { status: 400, headers: UPLOAD_CORS_HEADERS });
	}

	// Random key, not the original filename: uploads only ever need to be
	// found again by the key handed back in this response (stored as the
	// CMS field's value), never by name, and a random key sidesteps any
	// collision/sanitization concerns entirely.
	const extension = (request.headers.get('X-Filename') || '').match(/\.[a-zA-Z0-9]+$/)?.[0] || '.mp4';
	const key = `${crypto.randomUUID()}${extension}`;

	// Streams request.body straight into R2 rather than buffering it (e.g.
	// via request.arrayBuffer()) first — these files can be hundreds of MB,
	// well past what's safe to hold entirely in a Worker's memory at once.
	await env.RAW_UPLOADS_BUCKET.put(key, request.body);

	return new Response(JSON.stringify({ key }), {
		headers: { ...UPLOAD_CORS_HEADERS, 'Content-Type': 'application/json' },
	});
};

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
    console.log(`url.pathname is ${url.pathname}`);
		if (url.pathname === '/auth') {
			return handleAuth(url, env);
		}
		if (url.pathname === '/callback') {
			return handleCallback(url, env);
		}
		if (url.pathname === '/upload') {
			return handleUpload(request, env);
		}
		return new Response('Hello 👋');
	},
};
