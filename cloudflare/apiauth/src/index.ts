// The MIT License (MIT)
//
// Copyright (c) 2025 Kaito Udagawa
//
// See LICENSE for more information.

import { SignJWT } from "jose";
import { v7 as uuidv7 } from "uuid";

interface PrivateJwk extends JsonWebKey {
	kid?: string;
}

const ISSUER = "https://apiauth.vcpkg-obs.kaito.tokyo";
const TYPE_CLAIM = `${ISSUER}/type`;
const SCOPE_CLAIM = `${ISSUER}/scope`;
const AUDIENCE = "https://readwrite.vcpkg-obs.kaito.tokyo";

export async function handleServiceToken(
	request: Request,
	env: Env,
): Promise<Response> {
	switch (request.method) {
		case "POST": {
			const privateJwk: PrivateJwk = JSON.parse(env.PRIVATE_KEY_JSON);
			const { alg, kid } = privateJwk;
			if (!alg || alg !== "EdDSA") {
				throw new Error("Invalid alg in private key");
			}
			if (!kid || typeof kid !== "string") {
				throw new Error("Invalid kid in private key");
			}

			const formData = await request.formData();
			const sub = formData.get("sub");
			if (typeof sub !== "string" || !sub) {
				return new Response("Bad Request", { status: 400 });
			}

			const privateKey = await crypto.subtle.importKey(
				"jwk",
				privateJwk,
				{ name: "Ed25519" },
				false,
				["sign"],
			);

			const jwt = await new SignJWT({
				[TYPE_CLAIM]: "service-master",
				[SCOPE_CLAIM]: "accesstoken",
			})
				.setProtectedHeader({ alg, kid, typ: "JWT" })
				.setIssuer(ISSUER)
				.setSubject(sub)
				.setIssuedAt()
				.setExpirationTime("1y")
				.setJti(`${kid}_${uuidv7()}`)
				.setAudience(AUDIENCE)
				.sign(privateKey);

			return new Response(`Service master token:\n${jwt}`, {
				status: 200,
				headers: { "Content-Type": "text/plain" },
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
			case "/secured/service-master-token": {
				return handleServiceToken(request, env);
			}
			default: {
				return new Response("Not Found", { status: 404 });
			}
		}
	},
} satisfies ExportedHandler<Env>;
