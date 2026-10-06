import { SnowflakeFactory } from '@kirick/snowflake';
import { LRUCache } from 'lru-cache';
import * as v from 'valibot';
import { describe, expect, test, vi } from 'vitest';
import type { LRUCacheValue } from '../factory.js';
import { EcwtFactory } from '../main.js';
import { key, snowflake_options } from '../test-fixtures.js';

class IPAddress {
	readonly #address: string;

	constructor(address: string) {
		this.#address = address;
	}

	equals(other: IPAddress) {
		return this.#address === other.#address;
	}
}

const snowflakeFactory = new SnowflakeFactory(snowflake_options);
const ecwtFactory = new EcwtFactory({
	snowflakeFactory,
	options: { key },
});
const dataSchema = v.object({
	ip: v.pipe(
		v.string(),
		v.transform((address) => new IPAddress(address)),
	),
	bytes: v.instance(Buffer),
	permissions: v.object({ admin: v.boolean() }),
});

for (const has_cache of [false, true]) {
	describe(`freeze token data (${has_cache ? 'with cache' : 'without cache'})`, () => {
		test('create and verify preserve Buffers and validator classes', async () => {
			const validator = vi.fn(v.parser(dataSchema));
			const verifier = new EcwtFactory({
				lruCache: has_cache
					? new LRUCache<string, LRUCacheValue>({ max: 10 })
					: undefined,
				snowflakeFactory,
				options: { key, validator },
			});
			const data = {
				ip: '127.0.0.1',
				bytes: Buffer.from([127, 0, 0, 1]),
				permissions: { admin: false },
			};
			const ecwt = await ecwtFactory.create(data, { ttl: 10 });

			expect(Object.isFrozen(ecwt.data.permissions)).toBe(true);
			expect(ecwt.data.bytes).toBe(data.bytes);

			const ecwt_verified = await verifier.verify(ecwt.token);
			expect(Object.isFrozen(ecwt_verified.data)).toBe(true);
			expect(Object.isFrozen(ecwt_verified.data.permissions)).toBe(true);
			expect(Object.isFrozen(ecwt_verified.data.ip)).toBe(true);
			expect(ecwt_verified.data.ip).toBeInstanceOf(IPAddress);
			expect(ecwt_verified.data.ip.equals(new IPAddress(data.ip))).toBe(true);
			expect(Buffer.isBuffer(ecwt_verified.data.bytes)).toBe(true);
			expect(ecwt_verified.data.bytes).toStrictEqual(data.bytes);

			const ecwt_verified_again = await verifier.verify(ecwt.token);
			expect(validator).toHaveBeenCalledTimes(has_cache ? 1 : 2);
			expect(ecwt_verified_again.data === ecwt_verified.data).toBe(has_cache);
		});
	});
}
