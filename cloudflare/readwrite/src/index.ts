// The MIT License (MIT)
//
// Copyright (c) 2025 Kaito Udagawa
//
// See LICENSE for more information.

import { SignJWT } from "jose/jwt/sign";
import { jwtVerify } from "jose/jwt/verify";
import { createLocalJWKSet } from "jose/jwks/local";
import type { JWTPayload } from "jose";
import { v7 as uuidv7 } from "uuid";

import keys from "../keys.json";

const BINARYCACHE_PREFIX = "/binarycache/";

const ISSUER = "https://vcpkg-obs.kaito.tokyo";
const TYPE_CLAIM = `${ISSUER}/type`;
const SCOPE_CLAIM = `${ISSUER}/scope`;
const AUDIENCE = "https://readwrite.vcpkg-obs.kaito.tokyo";
const ACCESS_TOKEN_LIFE = "4h";

interface SecretJwk extends JsonWebKey {
	kid?: string;
}

export async function handleToken(
	request: Request,
	env: Env,
): Promise<Response> {
	switch (request.method) {
		case "POST": {
			const formData = await request.formData();

			const masterToken = formData.get("master_token");
			if (typeof masterToken !== "string" || !masterToken) {
				return new Response("Bad Request", { status: 400 });
			}

			const masterTokenPayload = await verifyMasterToken(masterToken);
			if (masterTokenPayload && masterTokenPayload.sub) {
				const accessToken = await generateAccessToken(JSON.parse(env.SECRET_KEY_JSON), masterTokenPayload.sub);
				return new Response(`${accessToken}\n`, {
					headers: { "Content-Type": "application/jwt" },
				});
			} else {
				return new Response("Unauthorized", { status: 401 });
			}
		}
		default: {
			return new Response("Method Not Allowed", {
				status: 405,
				headers: { Allow: "POST" },
			});
		}
	}
}

export async function verifyMasterToken(token: string): Promise<JWTPayload | undefined> {
    try {
		const JWKS = createLocalJWKSet(keys);

        const { payload } = await jwtVerify(token, JWKS, {
			algorithms: ['EdDSA'],
            issuer: ISSUER,
            audience: AUDIENCE,
			clockTolerance: 5,
            requiredClaims: ['sub', TYPE_CLAIM, SCOPE_CLAIM],
			typ: "JWT"
        });

		if (payload.ver !== '1.0') {
			console.error("ver claim mismatch");
			return;
		}

		if (payload[TYPE_CLAIM] !== 'master') {
			console.error("type claim mismatch");
			return;
		}

		if (payload[SCOPE_CLAIM] !== 'accesstoken') {
			console.error("scope claim mismatch");
			return;
		}

        return payload;
    } catch (e) {
		console.error("JWT verification failed:", e);
        return;
    }
}

export async function generateAccessToken(secretJwk: SecretJwk, sub: string): Promise<string> {
	const { alg, kid, kty } = secretJwk;
    if (kty !== "oct" || alg !== "HS256") {
        throw new Error("Invalid key type or algorithm for HMAC access token.");
    }

	const secretKey = await crypto.subtle.importKey(
		"jwk",
		secretJwk,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);

    const jwt = await new SignJWT({
        [TYPE_CLAIM]: "access",
        [SCOPE_CLAIM]: "binarycache",
		client_id: "readwrite",
		ver: "1.0",
    })
        .setProtectedHeader({ alg, kid, typ: "JWT" })
        .setIssuer(ISSUER)
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime(ACCESS_TOKEN_LIFE)
        .setAudience(AUDIENCE)
        .setJti(`${kid}_${uuidv7()}`)
        .sign(secretKey);

    return jwt;
}

export async function verifyAccessToken(secretJwk: SecretJwk, token: string): Promise<JWTPayload | undefined> {
	const secretKey = await crypto.subtle.importKey(
		"jwk",
		secretJwk,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["verify"],
	);

	try {
        const { payload } = await jwtVerify(token, secretKey, {
			algorithms: ['HS256'],
			clockTolerance: 5,
			typ: "JWT",
            audience: AUDIENCE,
            issuer: ISSUER,
            requiredClaims: ['sub', TYPE_CLAIM, SCOPE_CLAIM]
        });

		if (payload.ver !== '1.0') {
			console.error("ver claim mismatch");
			return;
		}

		if (payload[TYPE_CLAIM] !== 'access') {
			console.error("type claim mismatch");
			return;
		}

		if (payload[SCOPE_CLAIM] !== 'binarycache') {
			console.error("scope claim mismatch");
			return;
		}

		return payload;
    } catch (e) {
		console.error("JWT verification failed:", e);
		return;
    }
}

export async function handleBinaryCache(
	request: Request,
	env: Env,
	url: URL,
): Promise<Response> {
	const authorization = request.headers.get("authorization");
	if (!authorization || !authorization.startsWith("Bearer ")) {
		return new Response("Unauthorized", { status: 401 });
	}
	const accessToken = authorization.slice("Bearer ".length);

	const jwtPayload = await verifyAccessToken(JSON.parse(env.SECRET_KEY_JSON), accessToken);
	console.log(jwtPayload);
	if (!jwtPayload) {
		console.error("Access token verification failed");
		return new Response("Unauthorized", { status: 401 });
	}

	const key = url.pathname.slice(BINARYCACHE_PREFIX.length);

	if (key === "") {
		return new Response("Not Found", { status: 404 });
	}

	switch (request.method) {
		case "HEAD":
		case "GET": {
			const object = await env.R2_BUCKET.get(key, {
				onlyIf: request.headers,
				range: request.headers,
			});

			if (object === null) {
				return new Response("Not Found", { status: 404 });
			}

			const headers = new Headers();
			object.writeHttpMetadata(headers);
			headers.set("etag", object.httpEtag);

			if ("body" in object) {
				if (request.method === "HEAD") {
					return new Response(null, { status: 200, headers });
				} else {
					return new Response(object.body, {
						status: request.headers.get("range") === null ? 200 : 206,
						headers,
					});
				}
			} else {
				if (
					request.headers.has("if-match") ||
					request.headers.has("if-unmodified-since")
				) {
					return new Response(null, { status: 412, headers });
				} else {
					return new Response(null, { status: 304, headers });
				}
			}
		}

		case "PUT": {
			const existingObject = await env.R2_BUCKET.head(key);

			const result = await env.R2_BUCKET.put(key, request.body, {
				onlyIf: request.headers,
				httpMetadata: {
					contentType: request.headers.get("content-type") || undefined,
					cacheControl: "public, max-age=31536000, immutable"
				},
			});

			if (result === null) {
				return new Response("Precondition Failed", { status: 412 });
			} else {
				if (existingObject === null) {
					return new Response("Created", {
						status: 201,
						headers: { Location: url.href },
					});
				} else {
					return new Response("OK", { status: 200 });
				}
			}
		}

		default: {
			return new Response("Method Not Allowed", {
				status: 405,
				headers: { Allow: "GET, HEAD, PUT" },
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

		if (url.pathname.startsWith(BINARYCACHE_PREFIX)) {
			return handleBinaryCache(request, env, url)
		}

		switch (url.pathname) {
			case "/token": {
				return handleToken(request, env);
			}
			default: {
				return new Response("Not Found", { status: 404 });
			}
		}
	},
} satisfies ExportedHandler<Env>;
