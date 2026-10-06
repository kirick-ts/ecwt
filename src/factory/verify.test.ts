/* eslint-disable jsdoc/require-jsdoc */
// oxlint-disable max-lines-per-function

import { SnowflakeFactory } from '@kirick/snowflake';
import { aessiv } from '@noble/ciphers/aes.js';
import { encode as cborEncode } from 'cbor-x';
import { createClient } from 'redis';
import { afterAll, describe, expect, test } from 'vitest';
import {
	Ecwt,
	EcwtExpiredError,
	EcwtFactory,
	EcwtInvalidError,
	EcwtParseError,
	EcwtRevokedError,
} from '../main.js';
import { data_ecwt as data, key, snowflake_options } from '../test-fixtures.js';
import { base62 } from '../utils.js';

type VerifyMethod = 'verify' | 'safeVerify';

const namespace = `test-verify-${process.pid}`;
const redisClient = createClient({ socket: { port: 16379 } });
await redisClient.connect();

afterAll(async () => {
	await redisClient.DEL(`@ecwt:${namespace}:revoked`);
	await redisClient.quit();
});

const snowflakeFactory = new SnowflakeFactory(snowflake_options);
const snowflake = await snowflakeFactory.createSafe();
const ttl = 3600;
const ecwtFactory = new EcwtFactory({
	redisClient,
	snowflakeFactory,
	options: { key, namespace },
});

function encryptPayload(value: unknown, version = 0xf0) {
	return base62.encode(
		Buffer.concat([
			Buffer.from([version]),
			aessiv(key).encrypt(cborEncode(value)),
		]),
	);
}

async function expectInvalidError(
	method: VerifyMethod,
	token: string,
	errorClass: typeof EcwtInvalidError,
) {
	let result: { ecwt: Ecwt | null };

	if (method === 'verify') {
		let failure: unknown;
		try {
			await ecwtFactory.verify(token);
		} catch (error) {
			failure = error;
		}

		expect(failure).toBeInstanceOf(errorClass);
		if (!(failure instanceof EcwtInvalidError)) {
			expect.unreachable();
		}

		expect(failure.constructor).toBe(errorClass);
		result = failure;
	} else {
		const verified = await ecwtFactory.safeVerify(token);
		expect(verified.success).toBe(false);
		result = verified;
	}

	expect(result.ecwt).toBeInstanceOf(Ecwt);
	expect(result.ecwt?.token).toBe(token);
}

// Representative token format and parsing failures.
// Dependency errors should be normalized to EcwtParseError.
const parse_errors = [
	['EcwtParseError: truncated ciphertext', base62.encode(Buffer.from([0xf0]))],
	[
		'EcwtParseError: unsupported token version',
		encryptPayload([snowflake.toBuffer(), ttl, data], 0x02),
	],
	['Error: invalid Base62', '?'],
	['ValiError: invalid payload', encryptPayload(null)],
	['RangeError: short snowflake', encryptPayload([Buffer.alloc(7), ttl, data])],
] as const;

for (const method of ['verify', 'safeVerify'] as const) {
	describe(method, () => {
		test('TypeError: non-string token', async () => {
			const promise = ecwtFactory[method](null as unknown as string);

			await expect(promise).rejects.toThrow(TypeError);
			await expect(promise).rejects.toThrow('Token must be a string.');
		});

		for (const [name, token] of parse_errors) {
			test(name, async () => {
				const promise = ecwtFactory[method](token);

				await (method === 'verify'
					? expect(promise).rejects.toThrow(EcwtParseError)
					: expect(promise).resolves.toStrictEqual({
							success: false,
							ecwt: null,
						}));
			});
		}

		test('EcwtInvalidError: fractional TTL', async () => {
			const token = encryptPayload([snowflake.toBuffer(), 0.5, data]);

			await expectInvalidError(method, token, EcwtInvalidError);
		});

		test('EcwtExpiredError: expired token', async () => {
			const token = encryptPayload([snowflake.toBuffer(), -1, data]);

			await expectInvalidError(method, token, EcwtExpiredError);
		});

		test('EcwtRevokedError: revoked token', async () => {
			const ecwt = await ecwtFactory.create(data, { ttl });
			await ecwt.revoke();

			await expectInvalidError(method, ecwt.token, EcwtRevokedError);
		});
	});
}
