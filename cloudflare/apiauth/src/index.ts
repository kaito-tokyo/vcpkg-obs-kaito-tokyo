// SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
//
// SPDX-License-Identifier: Apache-2.0

import { SignJWT } from "jose/jwt/sign";
import { jwtVerify } from "jose/jwt/verify";
import { createRemoteJWKSet } from "jose/jwks/remote";
import { v7 as uuidv7 } from "uuid";

interface PrivateJwk extends JsonWebKey {
	kid?: string;
}

const ISSUER = "https://vcpkg-obs.kaito.tokyo";
const TYPE_CLAIM = `${ISSUER}/type`;
const SCOPE_CLAIM = `${ISSUER}/scope`;
const AUDIENCE = "https://readwrite.vcpkg-obs.kaito.tokyo";
const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_OIDC_JWKS = createRemoteJWKSet(
	new URL(`${GITHUB_OIDC_ISSUER}/.well-known/jwks`),
);
// The workflows request their id token for this audience, so a token minted
// for any other service cannot be replayed here.
const GITHUB_OIDC_AUDIENCE = "https://apiauth.vcpkg-obs.kaito.tokyo";
const GITHUB_OIDC_MASTER_TOKEN_LIFE = "15m";
// Numeric ids survive a rename, so they cannot be squatted by whoever picks up
// a freed repository name.
const GITHUB_OIDC_REPOSITORY_ID = "1114822803";
// The reusable workflows only set `environment: production` on main, so this
// single subject pins the repository, the branch and the environment at once,
// which puts the environment's protection rules in front of every cache write.
const GITHUB_OIDC_SUBJECTS = new Set([
	"repo:kaito-tokyo/vcpkg-obs-kaito-tokyo:environment:production",
]);

export async function signMasterToken(
	env: Env,
	sub: string,
): Promise<string> {
	const privateJwk: PrivateJwk = JSON.parse(env.PRIVATE_KEY_JSON);
	const { alg, kid } = privateJwk;
	if (!alg || alg !== "EdDSA") {
		throw new Error("Invalid alg in private key");
	}
	if (!kid || typeof kid !== "string") {
		throw new Error("Invalid kid in private key");
	}

	const privateKey = await crypto.subtle.importKey(
		"jwk",
		privateJwk,
		{ name: "Ed25519" },
		false,
		["sign"],
	);

	const jwt = new SignJWT({
		[TYPE_CLAIM]: "master",
		[SCOPE_CLAIM]: "accesstoken",
		client_id: "apiauth-github-oidc",
		ver: "1.0",
	})
		.setProtectedHeader({ alg, kid, typ: "JWT" })
		.setIssuer(ISSUER)
		.setSubject(sub)
		.setIssuedAt()
		.setExpirationTime(GITHUB_OIDC_MASTER_TOKEN_LIFE)
		.setJti(`${kid}_${uuidv7()}`)
		.setAudience(AUDIENCE);


	return jwt.sign(privateKey);
}

export async function verifyGitHubIdToken(
	idToken: string,
): Promise<string | undefined> {
	try {
		const { payload } = await jwtVerify(idToken, GITHUB_OIDC_JWKS, {
			algorithms: ["RS256"],
			audience: GITHUB_OIDC_AUDIENCE,
			clockTolerance: 5,
			issuer: GITHUB_OIDC_ISSUER,
			requiredClaims: ["sub", "repository_id"],
			typ: "JWT",
		});

		if (payload.repository_id !== GITHUB_OIDC_REPOSITORY_ID) {
			console.error("repository_id claim mismatch");
			return;
		}

		if (
			typeof payload.sub !== "string" ||
			!GITHUB_OIDC_SUBJECTS.has(payload.sub)
		) {
			console.error("sub claim mismatch");
			return;
		}

		return payload.sub;
	} catch (e) {
		console.error("GitHub id token verification failed:", e);
		return;
	}
}

export async function handleGitHubOidcToken(
	request: Request,
	env: Env,
): Promise<Response> {
	switch (request.method) {
		case "POST": {
			const authorization = request.headers.get("authorization");
			if (!authorization || !authorization.startsWith("Bearer ")) {
				return new Response("Unauthorized", { status: 401 });
			}

			const sub = await verifyGitHubIdToken(
				authorization.slice("Bearer ".length),
			);
			if (!sub) {
				return new Response("Unauthorized", { status: 401 });
			}

			// The subject is carried over verbatim so that the readwrite logs
			// name the GitHub identity the write was authorized for.
			const jwt = await signMasterToken(env, sub);

			return new Response(`${jwt}\n`, {
				status: 200,
				headers: {
					"Content-Type": "application/jwt",
					"Cache-Control": "no-store",
				},
			});
		}
		default: {
			return new Response("Method Not Allowed", {
				status: 405,
				headers: { Allow: "POST" },
			});
		}
	}
}

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		const url = new URL(request.url);
		switch (url.pathname) {
			case "/oidc/master-token": {
				return handleGitHubOidcToken(request, env);
			}
			default: {
				return new Response("Not Found", { status: 404 });
			}
		}
	},
} satisfies ExportedHandler<Env>;
