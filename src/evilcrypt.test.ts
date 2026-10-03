import { SnowflakeFactory } from '@kirick/snowflake';
import { encode as cborEncode } from 'cbor-x';
import { v1, v2 } from 'evilcrypt';
import { expect, test } from 'vitest';
import { EcwtFactory, EcwtParseError } from './main.js';
import { base62 } from './utils.js';

// Keep legacy token generation and compatibility checks in this removable file.
const key = Buffer.from(
	'54RoavO+7orGGCKqLXcMwNGFGbcnSEq22f9bJX3lT9lgEPSaRAMBaEnHgMQPTPXcifFvGZmDGzOFqUMfqXsAhQ==',
	'base64',
);

test.each([
	[0x01, v1],
	[0x02, v2],
] as const)(
	'decrypts EvilCrypt v%i tokens without a cache',
	async (version, cipher) => {
		const snowflakeFactory = new SnowflakeFactory({
			server_id: 0,
			worker_id: 0,
		});
		const snowflake = await snowflakeFactory.createSafe();
		const data = {
			user_id: 1,
			nick: 'legacy',
			binary: Buffer.from([0, 1, 255]),
		};
		const ttl = 60;
		const encrypted = await cipher.encrypt(
			cborEncode([snowflake.toBuffer(), ttl, data]),
			key,
		);
		const token = base62.encode(encrypted);
		const factory = new EcwtFactory({ snowflakeFactory, options: { key } });

		expect(encrypted[0]).toBe(version);

		const verified = await factory.verify(token);
		expect(verified.token).toBe(token);
		expect(verified.id).toBe(snowflake.toBase62());
		expect(verified.snowflake).toStrictEqual(snowflake);
		expect(verified.ts_expired).toBe(
			Math.floor(snowflake.timestamp / 1000) + ttl,
		);
		expect(verified.data).toStrictEqual(data);
		expect(Buffer.isBuffer(verified.data.binary)).toBe(true);

		const result = await factory.safeVerify(token);
		expect(result.success).toBe(true);
		expect(result.ecwt?.data).toStrictEqual(data);

		const wrongKeyFactory = new EcwtFactory({
			snowflakeFactory,
			options: { key: Buffer.alloc(64) },
		});
		await expect(wrongKeyFactory.verify(token)).rejects.toThrow(EcwtParseError);
	},
);
