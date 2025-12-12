export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		const url = new URL(request.url);
		const key = url.pathname.slice(1);
		const bucket = env.R2_BUCKET;

		if (key === "") {
			return new Response("Not Found", { status: 404 });
		}

		switch (request.method) {
			case "HEAD":
			case "GET": {
				const object = await bucket.get(key, {
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
							status: "range" in object ? 206 : 200,
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
				const existingObject = await bucket.head(key);

				const result = await bucket.put(key, request.body, {
					onlyIf: request.headers,
					httpMetadata: {
						contentType: request.headers.get("content-type") || undefined,
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
	},
} satisfies ExportedHandler<Env>;
