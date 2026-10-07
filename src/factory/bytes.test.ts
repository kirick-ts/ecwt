import { SnowflakeFactory } from '@kirick/snowflake';
import { aessiv } from '@noble/ciphers/aes.js';
import {
	Encoder as CborEncoder,
	decode as cborDecode,
	encode as cborEncode,
} from 'cbor-x';
import { expect, test } from 'vitest';
import { EcwtFactory } from '../main.js';
import { key, snowflake_options } from '../test-fixtures.js';
import { base62 } from '../utils.js';

for (const has_senml of [false, true]) {
	test(`0.4.1 binary compatibility (${has_senml ? 'with SenML' : 'without SenML'})`, async () => {
		const senml_key_map = has_senml ? { bytes: 1 } : undefined;
		const snowflakeFactory = new SnowflakeFactory(snowflake_options);
		const factory = new EcwtFactory({
			snowflakeFactory,
			options: { key, senml_key_map },
		});
		const data = {
			bytes: Uint8Array.of(255, 127, 0, 0, 1, 255).subarray(1, 5),
		};
		const ttl = 3600;
		const created = await factory.create(data, { ttl });

		// Reproduce the Buffer-based CBOR and encryption used in 0.4.1.
		const oldCodec = has_senml
			? new CborEncoder({ keyMap: senml_key_map })
			: { encode: cborEncode, decode: cborDecode };
		const oldPayload = [
			created.snowflake.toBuffer(),
			ttl,
			{ bytes: Buffer.from(data.bytes) },
		];
		const oldToken = base62.encode(
			Buffer.concat([
				Buffer.from([0xf0]),
				aessiv(key).encrypt(oldCodec.encode(oldPayload)),
			]),
		);
		expect(created.token).toBe(oldToken);

		const verified = await factory.verify(oldToken);
		expect(verified.id).toBe(created.id);
		expect(verified.data.bytes).toBeInstanceOf(Uint8Array);
		expect(verified.data).toStrictEqual(data);

		const oldDecoded = oldCodec.decode(
			Buffer.from(
				aessiv(key).decrypt(base62.decode(created.token).subarray(1)),
			),
		);
		expect(oldDecoded).toStrictEqual(oldPayload);
		expect(Buffer.isBuffer(oldDecoded[0])).toBe(true);
		expect(Buffer.isBuffer(oldDecoded[2].bytes)).toBe(true);
	});
}
