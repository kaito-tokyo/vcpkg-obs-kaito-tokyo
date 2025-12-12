// The MIT License (MIT)
//
// Copyright (c) 2025 Kaito Udagawa
//
// See LICENSE for more information.

import { SignJWT, JWK } from "jose";

export function decodeHexString(hexString: string): Uint8Array {
	const length = hexString.length;
	const uint8Array = new Uint8Array(length / 2);
	for (let i = 0, j = 0; i < length; i += 2, j++) {
		const hexByte = hexString.substring(i, i + 2);
		uint8Array[j] = parseInt(hexByte, 16);
	}
	return uint8Array;
}

export function loadPrivateKey(privateKeyHex: string): crypto.KeyObject {
	decodeHexString(privateKeyHex);
}

export async function handleServiceToken(
	request: Request,
	env: Env,
	url: URL,
): Promise<Response> {
	switch (request.method) {
		case "POST": {
			const payload = {};

			const jwt = await new SignJWT(payload)
				.setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
				.setIssuedAt()
				.setExpirationTime(0)
				.sign(privateKey);
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
			case "/service-token": {
				return handleServiceToken(request, env, url);
			}
			default: {
				return new Response("Not Found", { status: 404 });
			}
		}
	},
} satisfies ExportedHandler<Env>;
