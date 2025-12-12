import * as crypto from "node:crypto";

import { exportJWK } from "jose";

const keytype = "ci-master";
const keyname = process.argv[2];
if (!keyname) {
	throw new Error("Key name argument is required");
}

const kid = `${keytype}_${keyname}`;

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");

const privateKeyJwk = Object.fromEntries(
	[
		...Object.entries(await exportJWK(privateKey)),
		["alg", "EdDSA"],
		["key_ops", "sign"],
		["kid", kid],
		["use", "sig"],
	].sort(([a], [b]) => a.localeCompare(b)),
);

const publicKeyJwk = Object.fromEntries(
	[
		...Object.entries(await exportJWK(publicKey)),
		["alg", "EdDSA"],
		["key_ops", "verify"],
		["kid", kid],
		["use", "sig"],
	].sort(([a], [b]) => a.localeCompare(b)),
);

console.log(JSON.stringify(privateKeyJwk));
console.log(JSON.stringify(publicKeyJwk));
