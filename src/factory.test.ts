/* eslint-disable jsdoc/require-jsdoc */

import { SnowflakeFactory } from '@kirick/snowflake';
import { LRUCache } from 'lru-cache';
import { createClient } from 'redis';
import * as v from 'valibot';
import {
	describe,
	test,
	expect,
} from 'vitest';
import {
	Ecwt,
	EcwtFactory,
	EcwtParseError,
	EcwtInvalidError,
	EcwtExpiredError,
	EcwtRevokedError,
} from './main.js';
import type { LRUCacheValue } from './factory.js';

const redisClient = createClient({
	socket: {
		port: 16379,
	},
});
await redisClient.connect();

const lruCache = new LRUCache<string, LRUCacheValue>({ max: 100 });

const snowflakeFactory = new SnowflakeFactory({
	server_id: 0,
	worker_id: 0,
});

const key = Buffer.from(
	'54RoavO+7orGGCKqLXcMwNGFGbcnSEq22f9bJX3lT9lgEPSaRAMBaEnHgMQPTPXcifFvGZmDGzOFqUMfqXsAhQ==',
	'base64',
);

const ValiDataSchema = v.strictObject({
	user_id: v.pipe(
		v.number(),
		v.maxValue(10),
	),
	nick: v.pipe(
		v.string(),
		v.maxLength(10),
	),
});

const validator = v.parser(
	ValiDataSchema,
);

const ecwtFactory = new EcwtFactory({
	redisClient,
	lruCache,
	snowflakeFactory,
	options: {
		namespace: 'test',
		key,
		validator,
	},
});

async function measureTime(fn: (...args: unknown[]) => unknown): Promise<number> {
	const start = performance.now();
	await fn();
	const end = performance.now();

	return end - start;
}

describe('create token', () => {
	let ecwt: Ecwt | undefined;

	test('create', async () => {
		const ts_expired = Math.floor(Date.now() / 1000) + 10;

		ecwt = await ecwtFactory.create(
			{
				user_id: 1,
				nick: 'ecwt',
			},
			{ ttl: 10 },
		);

		expect(ecwt).toBeInstanceOf(Ecwt);
		expect(typeof ecwt.token).toBe('string');
		// console.log('token', ecwt.token);
		expect(ecwt.ts_expired).toBe(ts_expired);
		expect(
			ecwt.getTTL(),
		).toBe(10);
	});

	test('verify', async () => {
		if (!ecwt) {
			expect.unreachable();
		}

		const promise = ecwtFactory.verify(ecwt.token);

		await expect(promise).resolves.toBeInstanceOf(Ecwt);
	});

	test('safe verify', async () => {
		if (!ecwt) {
			expect.unreachable();
		}

		const result = await ecwtFactory.safeVerify(ecwt.token);

		expect(result.success).toBe(true);
		expect(result.ecwt).toBeInstanceOf(Ecwt);
	});

	test('verify with cache', async () => {
		if (!ecwt) {
			expect.unreachable();
		}

		const ecwt_verified = await ecwtFactory.verify(ecwt.token);

		expect(ecwt).toBeInstanceOf(Ecwt);
		expect(ecwt.token).toBe(ecwt_verified.token);
		expect(ecwt.id).toBe(ecwt_verified.id);
		expect(ecwt.snowflake).toStrictEqual(ecwt_verified.snowflake);
		expect(ecwt.ts_expired).toBe(ecwt_verified.ts_expired);
		expect(ecwt.data).toStrictEqual(ecwt_verified.data);
	});

	test('verify without cache', async () => {
		if (!ecwt) {
			expect.unreachable();
		}

		// @ts-expect-error Accessing private method
		ecwtFactory._purgeCache();

		const ecwt_verified = await ecwtFactory.verify(ecwt.token);

		expect(ecwt).toBeInstanceOf(Ecwt);
		expect(ecwt.token).toBe(ecwt_verified.token);
		expect(ecwt.id).toBe(ecwt_verified.id);
		expect(ecwt.snowflake).toStrictEqual(ecwt_verified.snowflake);
		expect(ecwt.ts_expired).toBe(ecwt_verified.ts_expired);
		expect(ecwt.data).toStrictEqual(ecwt_verified.data);
	});

	test('cache usage', async () => {
		if (!ecwt) {
			expect.unreachable();
		}

		const _ecwt = ecwt;

		// @ts-expect-error Accessing private method
		ecwtFactory._purgeCache();

		const time_no_cache = await measureTime(async () => {
			await ecwtFactory.verify(_ecwt.token);
		});
		// console.log('time_no_cache', time_no_cache);

		const time_with_cache = await measureTime(async () => {
			await ecwtFactory.verify(_ecwt.token);
		});
		// console.log('time_with_cache', time_with_cache);

		expect(time_with_cache).toBeLessThan(time_no_cache);
		expect(time_no_cache / time_with_cache).toBeGreaterThan(10);
	});

	test('create with invalid data', async () => {
		const promise = ecwtFactory.create(
			{
				user_id: 11,
				nick: 'ecwt',
			},
			{ ttl: 10 },
		);

		await expect(promise).rejects.toThrow(v.ValiError);
	});

	test('verify unparsable token', async () => {
		const promise = ecwtFactory.verify('deadbeef');

		await expect(promise).rejects.toThrow(EcwtParseError);
	});

	test('safe verify unparsable token', async () => {
		const result = await ecwtFactory.safeVerify('deadbeef');

		expect(result.success).toBe(false);
		expect(result.ecwt).toBe(null);
	});

	test('senml', async () => {
		if (!ecwt) {
			expect.unreachable();
		}

		const ecwtFactorySenml = new EcwtFactory({
			redisClient,
			lruCache,
			snowflakeFactory,
			options: {
				namespace: 'test',
				key,
				validator,
				senml_key_map: {
					user_id: 2,
					nick: 1,
				},
			},
		});

		const ecwt_senml = await ecwtFactorySenml.create(
			{
				user_id: 1,
				nick: 'ecwt',
			},
			{ ttl: 10 },
		);
		const ecwt_senml_verified = await ecwtFactorySenml.verify(ecwt.token);

		expect(ecwt_senml.data).toStrictEqual(ecwt_senml_verified.data);
		expect(ecwt_senml.token.length).toBeLessThan(ecwt.token.length);
	});
});

describe('token expiration', () => {
	test('with cache', async () => {
		const ecwt = await ecwtFactory.create(
			{
				user_id: 1,
				nick: 'kirick',
			},
			{ ttl: 1 },
		);

		await new Promise((resolve) => {
			setTimeout(resolve, 1100);
		});

		const promise = ecwtFactory.verify(ecwt.token);
		await expect(promise).rejects.toThrow(EcwtInvalidError);
		await expect(promise).rejects.toThrow(EcwtExpiredError);
	});

	test('without cache', async () => {
		const ecwt = await ecwtFactory.create(
			{
				user_id: 1,
				nick: 'kirick',
			},
			{ ttl: 1 },
		);

		// @ts-expect-error Accessing private method
		ecwtFactory._purgeCache();

		await new Promise((resolve) => {
			setTimeout(resolve, 1100);
		});

		const promise = ecwtFactory.verify(ecwt.token);
		await expect(promise).rejects.toThrow(EcwtExpiredError);
		await expect(promise).rejects.toThrow(EcwtInvalidError);
	});
});

describe('token revocation', () => {
	test('with cache', async () => {
		const ecwt = await ecwtFactory.create(
			{
				user_id: 1,
				nick: 'kirick',
			},
			{ ttl: 10 },
		);

		await ecwt.revoke();

		const promise = ecwtFactory.verify(ecwt.token);
		await expect(promise).rejects.toThrow(EcwtRevokedError);
		await expect(promise).rejects.toThrow(EcwtInvalidError);
	});

	test('without cache', async () => {
		const ecwt = await ecwtFactory.create(
			{
				user_id: 1,
				nick: 'kirick',
			},
			{ ttl: 10 },
		);

		// @ts-expect-error Accessing private method
		ecwtFactory._purgeCache();

		await ecwt.revoke();

		const promise = ecwtFactory.verify(ecwt.token);
		await expect(promise).rejects.toThrow(EcwtRevokedError);
		await expect(promise).rejects.toThrow(EcwtInvalidError);
	});
});
