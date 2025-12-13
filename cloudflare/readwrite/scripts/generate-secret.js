// The MIT License (MIT)
//
// Copyright (c) 2025 Kaito Udagawa
//
// See LICENSE for more information.

import { exportJWK } from "jose";

const keytype = "service-token";
const keyname = process.argv[2];
if (!keyname) {
	throw new Error("Key name argument is required");
}

const kid = `${keytype}_${keyname}`;

const secretKey = await crypto.subtle.generateKey(
	{
		name: "HMAC",
		hash: "SHA-256",
	},
	true,
	["sign", "verify"],
);

const secretJwk = Object.fromEntries(
	[
		...Object.entries(await exportJWK(secretKey)),
		["alg", "HS256"],
		["key_ops", ["sign", "verify"]],
		["kid", kid],
		["use", "sig"],
	].sort(([a], [b]) => a.localeCompare(b)),
);

console.log(JSON.stringify(secretJwk));
