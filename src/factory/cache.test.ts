// oxlint-disable max-lines-per-function

import { SnowflakeFactory } from '@kirick/snowflake';
import { describe, expect, test, vi } from 'vitest';
import { EcwtFactory, EcwtParseError } from '../main.js';
import { data_ecwt as data, key, snowflake_options } from '../test-fixtures.js';

const snowflakeFactory = new SnowflakeFactory(snowflake_options);
const ttl = 3600;

describe('private LRU cache', () => {
	test('shared options do not bypass another encryption key', async () => {
		const lru_cache = { max: 10 };
		const issuer = new EcwtFactory({
			snowflakeFactory,
			options: { key, lru_cache },
		});
		const ecwt = await issuer.create(data, { ttl });
		const verifier = new EcwtFactory({
			snowflakeFactory,
			options: { key: Buffer.alloc(64), lru_cache },
		});

		await expect(verifier.verify(ecwt.token)).rejects.toThrow(EcwtParseError);
		await expect(verifier.safeVerify(ecwt.token)).resolves.toStrictEqual({
			success: false,
			ecwt: null,
		});
		const verified = await issuer.verify(ecwt.token);
		expect(verified.data).toStrictEqual(data);
	});

	test('shared options do not bypass another validator', async () => {
		const lru_cache = { max: 10 };
		const issuer = new EcwtFactory({
			snowflakeFactory,
			options: { key, lru_cache },
		});
		const ecwt = await issuer.create(data, { ttl });
		const validator = vi.fn(() => {
			throw new Error('Payload rejected.');
		});
		const verifier = new EcwtFactory({
			snowflakeFactory,
			options: { key, lru_cache, validator },
		});

		await expect(verifier.verify(ecwt.token)).rejects.toThrow(EcwtParseError);
		await expect(verifier.safeVerify(ecwt.token)).resolves.toStrictEqual({
			success: false,
			ecwt: null,
		});
		expect(validator).toHaveBeenCalledTimes(2);
		const verified = await issuer.verify(ecwt.token);
		expect(verified.data).toStrictEqual(data);
	});

	test('eviction and purging affect only the owning factory', async () => {
		const lru_cache = { max: 1 };
		const validate_issuer = vi.fn(() => data);
		const validate_verifier = vi.fn(() => data);
		const issuer = new EcwtFactory({
			snowflakeFactory,
			options: { key, lru_cache, validator: validate_issuer },
		});
		const verifier = new EcwtFactory({
			snowflakeFactory,
			options: { key, lru_cache, validator: validate_verifier },
		});
		const ecwt = await issuer.create(data, { ttl });
		await verifier.verify(ecwt.token);
		await issuer.create(data, { ttl });
		await issuer.verify(ecwt.token);
		expect(validate_issuer).toHaveBeenCalledTimes(3);

		issuer._purgeCache();
		await issuer.verify(ecwt.token);
		await verifier.verify(ecwt.token);
		expect(validate_issuer).toHaveBeenCalledTimes(4);
		expect(validate_verifier).toHaveBeenCalledTimes(1);
	});
});
