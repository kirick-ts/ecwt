/* eslint-disable jsdoc/require-jsdoc */
// oxlint-disable max-lines-per-function

import { SnowflakeFactory } from '@kirick/snowflake';
import * as v from 'valibot';
import { afterEach, expect, test, vi } from 'vitest';
import { EcwtFactory } from '../main.js';
import { key, snowflake_options } from '../test-fixtures.js';

const dataSchema = v.object({
	bytes: v.instance(Uint8Array),
	permissions: v.object({ admin: v.boolean() }),
	date: v.date(),
	scopes: v.set(v.string()),
});
type Data = v.InferOutput<typeof dataSchema>;

function createData(): Data {
	return {
		bytes: Uint8Array.of(127, 0, 0, 1),
		permissions: { admin: false },
		date: new Date(1000),
		scopes: new Set(['read']),
	};
}

function mutateData(data: Data): void {
	// Mutate the entire backing array to catch views into cached CBOR bytes.
	// eslint-disable-next-line unicorn/no-unsafe-buffer-conversion
	new Uint8Array(data.bytes.buffer).fill(0);
	data.permissions.admin = true;
	data.date.setTime(0);
	data.scopes.add('write');
}

afterEach(() => {
	vi.restoreAllMocks();
});

for (const has_cache of [false, true]) {
	for (const has_senml of [false, true]) {
		test(`fresh token data (${has_cache ? 'with cache' : 'without cache'}, ${has_senml ? 'with SenML' : 'without SenML'})`, async () => {
			const snowflakeFactory = new SnowflakeFactory(snowflake_options);
			const validator = vi.fn(v.parser(dataSchema));
			const ecwtFactory = new EcwtFactory({
				snowflakeFactory,
				options: {
					key,
					validator,
					lru_cache: has_cache ? { max: 10 } : undefined,
					senml_key_map: has_senml ? { bytes: 1, permissions: 2 } : undefined,
				},
			});
			const data = createData();
			const expected = createData();
			const created = await ecwtFactory.create(data, { ttl: 10 });
			mutateData(data);

			// Exercise both encoded bytes from create and decrypted bytes from verify.
			ecwtFactory._purgeCache();
			const verified = await ecwtFactory.verify(created.token);
			validator.mockClear();
			const parse = vi.spyOn(snowflakeFactory, 'parse');

			for (const ecwt of [created, verified]) {
				const first = ecwt.data as Data;
				expect(first).toStrictEqual(expected);
				mutateData(first);
				const second = ecwt.data;
				expect(second).not.toBe(first);
				expect(second.bytes.buffer).not.toBe(first.bytes.buffer);
				expect(second).toStrictEqual(expected);
			}

			expect(validator).toHaveBeenCalledTimes(4);
			expect(parse).not.toHaveBeenCalled();

			const verified_again = await ecwtFactory.verify(created.token);
			expect(verified_again.data).toStrictEqual(expected);
		});
	}
}
