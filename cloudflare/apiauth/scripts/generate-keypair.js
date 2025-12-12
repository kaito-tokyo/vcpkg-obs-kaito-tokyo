import * as crypto from 'node:crypto';

import { exportJWK } from 'jose';
import { v7 as uuidv7 } from 'uuid';

const KID = crypto.randomUUID();

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
	privateKeyEncoding: { type: 'pkcs8', format: 'der' }
})

const publicKeyJwk = Object.fromEntries([
	...Object.entries(await exportJWK(publicKey)),
	["alg", 'EdDSA'],
	["kid", uuidv7()],
	["use", 'sig'],
	["key_ops", "verify"]
].sort(([a], [b]) => a.localeCompare(b)));

console.log(privateKey.toString('hex'));
console.log(JSON.stringify(publicKeyJwk));

