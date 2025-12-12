// The MIT License (MIT)
//
// Copyright (c) 2025 Kaito Udagawa
//
// See LICENSE for more information.

import { SignJWT, JWK } from "jose";
import * as crypto from "node:crypto";

export async function handleNewServiceToken(
	request: Request,
	env: Env,
	url: URL,
): Promise<Response> {
	switch (request.method) {
		case "POST": {
			return new Response("Not Implemented", { status: 501 });
		}
		default: {
			return new Response("Method Not Allowed", {
				status: 405,
				headers: { Allow: "POST" },
			});
		}
	}
}

export async function handleToken(
	request: Request,
	env: Env,
	url: URL,
): Promise<Response> {
	return new Response("Not Implemented", { status: 501 });
}

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		const url = new URL(request.url);
		switch (url.pathname) {
			case "/token": {
				return handleToken(request, env, url);
			}
			case "/service-token": {
				return handleNewServiceToken(request, env, url);
			}
			default: {
				return new Response("Not Found", { status: 404 });
			}
		}
	},
} satisfies ExportedHandler<Env>;
