/* eslint-disable jsdoc/require-jsdoc */
// oxlint-disable max-lines-per-function

import { SnowflakeFactory } from '@kirick/snowflake';
import { createClient } from 'redis';
import * as v from 'valibot';
import { describe, expect, test } from 'vitest';
import {
	Ecwt,
	EcwtExpiredError,
	EcwtFactory,
	EcwtInvalidError,
	EcwtRevokedError,
} from './main.js';
import {
	data_ecwt,
	data_kirick,
	key,
	snowflake_options,
} from './test-fixtures.js';
import { base62 } from './utils.js';

const redisClient = createClient({
	socket: {
		port: 16379,
	},
});
await redisClient.connect();
await redisClient.flushAll();

const dataSchema = v.strictObject({
	user_id: v.pipe(v.number(), v.maxValue(10)),
	nick: v.pipe(v.string(), v.maxLength(10)),
});
const validator = v.parser(dataSchema);

type Data = v.InferOutput<typeof dataSchema>;

const lru_cache = { max: 100 };

const snowflakeFactory = new SnowflakeFactory(snowflake_options);

function createEcwtFactory() {
	return new EcwtFactory({
		redisClient,
		snowflakeFactory,
		options: {
			lru_cache,
			namespace: 'test',
			key,
			validator,
		},
	});
}

const ecwtFactory = createEcwtFactory();

describe('create token', () => {
	let ecwt: Ecwt<Data> | undefined;

	test('create', async () => {
		const ts_expired = Math.floor(Date.now() / 1000) + 10;

		ecwt = await ecwtFactory.create(data_ecwt, { ttl: 10 });

		expect(ecwt).toBeInstanceOf(Ecwt);
		expect(typeof ecwt.token).toBe('string');
		expect(base62.decode(ecwt.token)[0]).toBe(0xf0);
		// console.log('token', ecwt.token);
		expect(ecwt.ts_expired).toBe(ts_expired);
		expect(ecwt.getTTL()).toBe(10);
	});

	test('verify', async () => {
		if (!ecwt) {
			expect.unreachable();
		}

		const ecwt_verified = await ecwtFactory.verify(ecwt.token);

		expect(ecwt_verified).toBeInstanceOf(Ecwt);
		expect(ecwt_verified.token).toBe(ecwt.token);
		expect(ecwt_verified.id).toBe(ecwt.id);
		expect(ecwt_verified.snowflake).toStrictEqual(ecwt.snowflake);
		expect(ecwt_verified.ts_expired).toBe(ecwt.ts_expired);
		expect(ecwt_verified.data).toStrictEqual(ecwt.data);
	});

	test('safe verify', async () => {
		if (!ecwt) {
			expect.unreachable();
		}

		const result = await ecwtFactory.safeVerify(ecwt.token);

		expect(result.success).toBe(true);
		expect(result.ecwt).toBeInstanceOf(Ecwt);
	});

	test('create with invalid data', async () => {
		const promise = ecwtFactory.create(
			{
				...data_ecwt,
				user_id: 11,
			},
			{ ttl: 10 },
		);

		await expect(promise).rejects.toThrow(v.ValiError);
	});

	test('senml', async () => {
		if (!ecwt) {
			expect.unreachable();
		}

		const ecwtFactorySenml = new EcwtFactory({
			redisClient,
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

		const ecwt_senml = await ecwtFactorySenml.create(data_ecwt, { ttl: 10 });
		const ecwt_senml_verified = await ecwtFactorySenml.verify(ecwt_senml.token);

		expect(ecwt_senml.data).toStrictEqual(ecwt_senml_verified.data);
		expect(ecwt_senml.token.length).toBeLessThan(ecwt.token.length);
	});
});

describe('token expiration', () => {
	test('rejects a token after its TTL elapses', async () => {
		const ecwt = await ecwtFactory.create(data_kirick, { ttl: 1 });

		await new Promise((resolve) => {
			setTimeout(resolve, 1100);
		});

		const promise = ecwtFactory.verify(ecwt.token);
		await expect(promise).rejects.toThrow(EcwtInvalidError);
		await expect(promise).rejects.toThrow(EcwtExpiredError);
	});
});

describe('token revocation', () => {
	test('with cache', async () => {
		const ecwt = await ecwtFactory.create(data_kirick, { ttl: 100 });

		await ecwt.revoke();

		const promise = ecwtFactory.verify(ecwt.token);
		await expect(promise).rejects.toThrow(EcwtRevokedError);
		await expect(promise).rejects.toThrow(EcwtInvalidError);
	});

	describe('migration', () => {
		const REDIS_KEY = '@ecwt:test:revoked';

		test('actual migration', async () => {
			await redisClient
				.MULTI()
				.DEL(REDIS_KEY)
				.addCommand([
					'ZADD',
					REDIS_KEY,
					String(Date.now() + 10_000),
					'deadbeef',
				])
				.EXEC();

			// we use a new factory to test that the "migrated" flag is cleared
			const ecwtFactory2 = createEcwtFactory();

			const ecwt = await ecwtFactory2.create(data_kirick, { ttl: 100 });

			// force migration
			await ecwtFactory2.verify(ecwt.token);

			const type = await redisClient.TYPE(REDIS_KEY);
			expect(type).toBe('hash');

			const data = await redisClient.HGETALL(REDIS_KEY);
			// redis client uses object with null prototype, breaking strict equality
			// oh my god.
			expect(structuredClone(data)).toStrictEqual({ deadbeef: '' });

			const ttl = await redisClient.sendCommand([
				'HPTTL',
				REDIS_KEY,
				'FIELDS',
				'1',
				'deadbeef',
			]);
			if (!Array.isArray(ttl)) {
				throw new TypeError('ttl is not an array');
			}

			// console.info(ttl[0]);

			expect(ttl[0]).toBeLessThan(10_000);
			expect(ttl[0]).toBeGreaterThan(9000);
		});

		test('already migrated', async () => {
			await redisClient
				.MULTI()
				.DEL(REDIS_KEY)
				.HSET(REDIS_KEY, 'deadbeef', '')
				.HPEXPIRE(REDIS_KEY, 'deadbeef', 10_000)
				.EXEC();

			// we use a new factory to test that the "migrated" flag is cleared
			const ecwtFactory2 = createEcwtFactory();

			const ecwt = await ecwtFactory2.create(data_kirick, { ttl: 100 });

			// force migration
			await ecwtFactory2.verify(ecwt.token);

			const type = await redisClient.TYPE(REDIS_KEY);
			expect(type).toBe('hash');

			const data = await redisClient.HGETALL(REDIS_KEY);
			// redis client uses object with null prototype, breaking strict equality
			// oh my god.
			expect(structuredClone(data)).toStrictEqual({ deadbeef: '' });
		});
	});
});
