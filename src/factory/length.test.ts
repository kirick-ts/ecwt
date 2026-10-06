/* eslint-disable jsdoc/require-jsdoc */
// oxlint-disable max-lines-per-function

import { SnowflakeFactory } from '@kirick/snowflake';
import { LRUCache } from 'lru-cache';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { LRUCacheValue } from '../factory.js';
import { EcwtFactory, EcwtParseError } from '../main.js';
import { data_ecwt as data, key, snowflake_options } from '../test-fixtures.js';
import { base62 } from '../utils.js';

const snowflakeFactory = new SnowflakeFactory(snowflake_options);
const ttl = 3600;

function createEcwtFactory(
	max_token_length?: number,
	lru_cache?: LRUCache.Options<string, LRUCacheValue, unknown>,
) {
	return new EcwtFactory({
		snowflakeFactory,
		options: { key, max_token_length, lru_cache },
	});
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe('maximum token length option', () => {
	const invalid_lengths = [
		0,
		-1,
		0.5,
		// oxlint-disable-next-line unicorn/prefer-number-properties
		NaN,
		Infinity,
		Number.MAX_SAFE_INTEGER + 1,
	];

	for (const max_token_length of invalid_lengths) {
		test(`invalid length ${max_token_length}`, () => {
			expect(() => createEcwtFactory(max_token_length)).toThrow(
				new TypeError(
					'Option max_token_length must be a positive safe integer.',
				),
			);
		});
	}
});

describe('create token length', () => {
	test('accepts the exact limit and rejects one character over it', async () => {
		const ecwt = await createEcwtFactory().create(data, { ttl });
		// Reuse the ID so deterministic encryption produces the same token.
		vi.spyOn(snowflakeFactory, 'createSafe').mockResolvedValue(ecwt.snowflake);
		const max_token_length = ecwt.token.length;
		const accepted = await createEcwtFactory(max_token_length).create(data, {
			ttl,
		});
		expect(accepted.token).toBe(ecwt.token);

		const set = vi.spyOn(LRUCache.prototype, 'set');
		const promise = createEcwtFactory(max_token_length - 1, { max: 10 }).create(
			data,
			{ ttl },
		);
		await expect(promise).rejects.toThrow(
			new RangeError(
				`Token exceeds maximum length of ${max_token_length - 1} characters.`,
			),
		);
		expect(set).not.toHaveBeenCalled();
	});

	test('defaults to 4000 characters and accepts a larger configured limit', async () => {
		const payload = { value: 'x'.repeat(3200) };
		const ecwt = await createEcwtFactory(5000).create(payload, { ttl });
		expect(base62.decode(ecwt.token).length).toBeLessThan(4000);
		expect(ecwt.token.length).toBeGreaterThan(4000);
		expect(ecwt.token.length).toBeLessThanOrEqual(5000);
		const verified = await createEcwtFactory(5000).verify(ecwt.token);
		expect(verified.data).toStrictEqual(payload);

		await expect(createEcwtFactory().create(payload, { ttl })).rejects.toThrow(
			new RangeError('Token exceeds maximum length of 4000 characters.'),
		);
		const decode = vi.spyOn(base62, 'decode');
		await expect(createEcwtFactory().verify(ecwt.token)).rejects.toThrow(
			EcwtParseError,
		);
		await expect(
			createEcwtFactory().safeVerify(ecwt.token),
		).resolves.toStrictEqual({
			success: false,
			ecwt: null,
		});
		expect(decode).not.toHaveBeenCalled();
	});

	test('rejects oversized buffers before Base62 encoding', async () => {
		const encode = vi.spyOn(base62, 'encode');
		// The binary fits the limit, but its Base62 representation does not.
		const promise = createEcwtFactory().create(
			{ value: Buffer.alloc(3200) },
			{ ttl },
		);

		await expect(promise).rejects.toThrow(RangeError);
		expect(encode).not.toHaveBeenCalled();
	});
});

for (const has_cache of [false, true]) {
	describe(`verify token length (${has_cache ? 'with cache' : 'without cache'})`, () => {
		test('accepts the exact limit and rejects longer tokens before decoding', async () => {
			const ecwt = await createEcwtFactory().create(data, { ttl });
			const lru_cache = has_cache ? { max: 10 } : undefined;
			const accepted = createEcwtFactory(ecwt.token.length, lru_cache);
			const verified = await accepted.verify(ecwt.token);
			const result = await accepted.safeVerify(ecwt.token);
			expect(verified.data).toStrictEqual(data);
			expect(result.success).toBe(true);

			const decode = vi.spyOn(base62, 'decode');
			const get = vi.spyOn(LRUCache.prototype, 'get');
			const rejected = createEcwtFactory(ecwt.token.length - 1, lru_cache);
			await expect(rejected.verify(ecwt.token)).rejects.toThrow(EcwtParseError);
			await expect(rejected.safeVerify(ecwt.token)).resolves.toStrictEqual({
				success: false,
				ecwt: null,
			});
			expect(decode).not.toHaveBeenCalled();
			expect(get).not.toHaveBeenCalled();
		});
	});
}
