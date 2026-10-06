/* eslint-disable jsdoc/require-jsdoc */

import { SnowflakeFactory } from '@kirick/snowflake';
import { aessiv } from '@noble/ciphers/aes.js';
import { encode as cborEncode } from 'cbor-x';
import type { LRUCache } from 'lru-cache';
import { describe, expect, test } from 'vitest';
import { type LRUCacheValue, TTL_MAX } from '../factory.js';
import { EcwtFactory, EcwtInvalidError } from '../main.js';
import { data_ecwt as data, key, snowflake_options } from '../test-fixtures.js';
import { base62 } from '../utils.js';

const snowflakeFactory = new SnowflakeFactory(snowflake_options);

// Ten 365-day years in seconds.
const valid_ttls = [1, 60, 3600, TTL_MAX - 1, TTL_MAX];
const invalid_ttls = [
	// oxlint-disable-next-line unicorn/prefer-number-properties
	NaN,
	Infinity,
	-Infinity,
	0.5,
	-0.5,
	Number.MAX_SAFE_INTEGER + 1,
];
const excessive_ttls = [TTL_MAX + 1, Number.MAX_SAFE_INTEGER];

function createEcwtFactory(
	lru_cache?: LRUCache.Options<string, LRUCacheValue, unknown>,
) {
	return new EcwtFactory({
		snowflakeFactory,
		options: { key, lru_cache },
	});
}

async function verifyToken(ttl: number, has_cache: boolean) {
	const snowflake = await snowflakeFactory.createSafe();
	const token_raw = cborEncode([snowflake.toBuffer(), ttl, data]);
	const token = base62.encode(
		Buffer.concat([Buffer.from([0xf0]), aessiv(key).encrypt(token_raw)]),
	);
	const ecwtFactory = createEcwtFactory(has_cache ? { max: 100 } : undefined);
	if (has_cache) {
		// Warm the private cache, including payloads rejected by TTL validation.
		await ecwtFactory.safeVerify(token);
	}

	return ecwtFactory.verify(token);
}

describe('create token TTL', () => {
	for (const ttl of valid_ttls) {
		test(`valid TTL ${ttl}`, async () => {
			const ecwtFactory = createEcwtFactory();
			const ecwt = await ecwtFactory.create(data, { ttl });
			const ecwt_verified = await ecwtFactory.verify(ecwt.token);

			expect(ecwt_verified.data).toStrictEqual(data);
			expect(ecwt_verified.ts_expired).toBe(
				Math.floor(ecwt.snowflake.timestamp / 1000) + ttl,
			);
		});
	}

	for (const ttl of invalid_ttls) {
		test(`invalid TTL ${ttl}`, async () => {
			const ecwtFactory = createEcwtFactory();
			const promise = ecwtFactory.create(data, { ttl });

			await expect(promise).rejects.toThrow(TypeError);
		});
	}

	for (const ttl of excessive_ttls) {
		test(`TTL over 10 years ${ttl}`, async () => {
			const ecwtFactory = createEcwtFactory();
			const promise = ecwtFactory.create(data, { ttl });

			await expect(promise).rejects.toThrow(TypeError);
		});
	}
});

for (const has_cache of [false, true]) {
	describe(`verify token TTL (${has_cache ? 'with cache' : 'without cache'})`, () => {
		for (const ttl of valid_ttls) {
			test(`valid TTL ${ttl}`, async () => {
				const ecwt = await verifyToken(ttl, has_cache);

				expect(ecwt.data).toStrictEqual(data);
				expect(ecwt.ts_expired).toBe(
					Math.floor(ecwt.snowflake.timestamp / 1000) + ttl,
				);
			});
		}

		for (const ttl of invalid_ttls) {
			test(`invalid TTL ${ttl}`, async () => {
				const promise = verifyToken(ttl, has_cache);

				await expect(promise).rejects.toThrow();
			});
		}

		for (const ttl of excessive_ttls) {
			test(`TTL over 10 years ${ttl}`, async () => {
				const promise = verifyToken(ttl, has_cache);

				await expect(promise).rejects.toThrow(EcwtInvalidError);
			});
		}
	});
}
