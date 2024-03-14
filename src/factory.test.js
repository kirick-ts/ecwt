
const {
	describe,
	test,
	expect,
} = await import(
	'Bun' in globalThis
		? 'bun:test'
		: 'vitest'
);

import { SnowflakeFactory } from '@kirick/snowflake';
import { LRUCache }         from 'lru-cache';
import { createClient }     from 'redis';
import * as v               from 'valibot';
import { EcwtFactory }      from './factory.js';
import { Ecwt }             from './token.js';
import {
	EcwtExpiredError,
	EcwtRevokedError }      from './utils/errors.js';

const redisClient = createClient({
	socket: {
		host: 'localhost',
		port: 16274,
	},
});
await redisClient.connect();

const lruCache = new LRUCache({
	max: 100,
});

const snowflakeFactory = new SnowflakeFactory({
	server_id: 0,
	worker_id: 0,
});

const key = Buffer.from(
	'54RoavO+7orGGCKqLXcMwNGFGbcnSEq22f9bJX3lT9lgEPSaRAMBaEnHgMQPTPXcifFvGZmDGzOFqUMfqXsAhQ==',
	'base64',
);
const validator = (value) => v.parse(
	v.object({
		user_id: v.number([
			v.maxValue(10),
		]),
		nick: v.string([
			v.maxLength(10),
		]),
	}),
	value,
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

/**
 * @async
 * @param {Function} fn -
 * @returns {Promise<number>} -
 */
async function measureTime(fn) {
	const start = performance.now();
	await fn();
	const end = performance.now();

	return end - start;
}

describe('create token', () => {
	let ecwt;

	test('create', async () => {
		const ts_expired = Math.floor(Date.now() / 1000) + 10;

		ecwt = await ecwtFactory.create(
			{
				user_id: 1,
				nick: 'ecwt',
			},
			{
				ttl: 10,
			},
		);

		expect(ecwt).toBeInstanceOf(Ecwt);
		expect(typeof ecwt.token).toBe('string');
		// console.log('token', ecwt.token);
		expect(ecwt.ts_expired).toBe(ts_expired);
		expect(
			ecwt.getTTL(),
		).toBe(10);

		await ecwtFactory.verify(ecwt.token);
	});

	test('verify with cache', async () => {
		const ecwt_verified = await ecwtFactory.verify(ecwt.token);

		expect(ecwt).toBeInstanceOf(Ecwt);
		expect(ecwt.token).toBe(ecwt_verified.token);
		expect(ecwt.id).toBe(ecwt_verified.id);
		expect(ecwt.snowflake).toStrictEqual(ecwt_verified.snowflake);
		expect(ecwt.ts_expired).toBe(ecwt_verified.ts_expired);
		expect(ecwt.data).toStrictEqual(ecwt_verified.data);
	});

	test('verify without cache', async () => {
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
		ecwtFactory._purgeCache();

		const time_no_cache = await measureTime(async () => {
			await ecwtFactory.verify(ecwt.token);
		});
		// console.log('time_no_cache', time_no_cache);

		const time_with_cache = await measureTime(async () => {
			await ecwtFactory.verify(ecwt.token);
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
			{
				ttl: 10,
			},
		);

		await expect(promise).rejects.toThrow(v.ValiError);
	});

	test('senml', async () => {
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
			{
				ttl: 10,
			},
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
			{
				ttl: 1,
			},
		);

		await new Promise((resolve) => {
			setTimeout(resolve, 1100);
		});

		await expect(
			ecwtFactory.verify(ecwt.token),
		).rejects.toThrow(EcwtExpiredError);
	});

	test('without cache', async () => {
		const ecwt = await ecwtFactory.create(
			{
				user_id: 1,
				nick: 'kirick',
			},
			{
				ttl: 1,
			},
		);

		ecwtFactory._purgeCache();

		await new Promise((resolve) => {
			setTimeout(resolve, 1100);
		});

		await expect(
			ecwtFactory.verify(ecwt.token),
		).rejects.toThrow(EcwtExpiredError);
	});
});

describe('token revocation', () => {
	test('with cache', async () => {
		const ecwt = await ecwtFactory.create(
			{
				user_id: 1,
				nick: 'kirick',
			},
			{
				ttl: 10,
			},
		);

		await ecwt.revoke();

		await expect(
			ecwtFactory.verify(ecwt.token),
		).rejects.toThrow(EcwtRevokedError);
	});

	test('without cache', async () => {
		const ecwt = await ecwtFactory.create(
			{
				user_id: 1,
				nick: 'kirick',
			},
			{
				ttl: 10,
			},
		);

		ecwtFactory._purgeCache();

		await ecwt.revoke();

		await expect(
			ecwtFactory.verify(ecwt.token),
		).rejects.toThrow(EcwtRevokedError);
	});
});
