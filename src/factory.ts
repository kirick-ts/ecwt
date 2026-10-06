import type { Snowflake, SnowflakeFactory } from '@kirick/snowflake';
import { aessiv } from '@noble/ciphers/aes.js';
import {
	Encoder as CborEncoder,
	decode as cborDecode,
	encode as cborEncode,
} from 'cbor-x';
import { decrypt as evilcryptDecrypt } from 'evilcrypt';
import { LRUCache } from 'lru-cache';
import type {
	RedisClientType,
	RedisFunctions,
	RedisModules,
	RedisScripts,
} from 'redis';
import * as v from 'valibot';
import {
	EcwtExpiredError,
	EcwtInvalidError,
	EcwtParseError,
	EcwtRevokedError,
} from './errors.js';
import { Ecwt } from './token.js';
import { base62 } from './utils.js';

export type LRUCacheValue<
	D extends Record<string, unknown> = Record<string, unknown>,
> = {
	snowflake: Snowflake;
	ttl_initial: number;
	data: D;
};
type RedisClient = RedisClientType<RedisModules, RedisFunctions, RedisScripts>;
type EcwtFactoryArguments<D extends Record<string, unknown>> = {
	/** RedisClient instance. If not provided, tokens can not be revoked and can not be checked for revocation. */
	redisClient?: RedisClient;
	/** SnowflakeFactory instance. Generates unique IDs for tokens. */
	snowflakeFactory: SnowflakeFactory;
	options: {
		/** Namespace for Redis keys. */
		namespace?: string;
		/** Encryption key, 64 bytes. */
		key: Buffer;
		/**
		 * Options for a private LRU cache. If not provided, tokens will be decrypted every time they are verified.
		 * @see https://npmx.dev/package/lru-cache#user-content-usage
		 */
		lru_cache?: LRUCache.Options<string, LRUCacheValue<D>, unknown>;
		/** Maximum serialized token length in Base62 characters. Defaults to 4000. */
		max_token_length?: number;
		/** Validator for token data. Should return validated value or throw an error. */
		validator?: (value: unknown) => D;
		/** Payload object keys mapped for their SenML keys. */
		senml_key_map?: Record<string, number>;
	};
};

const REDIS_PREFIX = '@ecwt:';
const BASE62_EXPANSION_FACTOR = 8 / Math.log2(62);
export const TTL_MAX: number = 2 * 365 * 24 * 60 * 60;

const tokenSchema = v.tuple([
	v.pipe(
		v.unknown(),
		v.check((value) => Buffer.isBuffer(value)),
		v.transform((value) => value as Buffer<ArrayBufferLike>),
	),
	v.number(),
	v.record(v.string(), v.unknown()),
]);

export class EcwtFactory<
	const D extends Record<string, unknown> = Record<string, unknown>,
> {
	#redisClient: RedisClient | undefined;
	#lruCache: LRUCache<string, LRUCacheValue<D>> | undefined;
	#snowflakeFactory: SnowflakeFactory;
	#redis_key_revoked: string;
	#encryption_key: Buffer;
	#max_token_length = 4000;
	#validator: ((value: unknown) => D) | undefined;
	#cborEncoder: CborEncoder | null = null;

	constructor({
		redisClient,
		snowflakeFactory,
		options,
	}: EcwtFactoryArguments<D>) {
		this.#redisClient = redisClient;
		this.#lruCache = options.lru_cache
			? new LRUCache(options.lru_cache)
			: undefined;
		this.#snowflakeFactory = snowflakeFactory;

		this.#redis_key_revoked = `${REDIS_PREFIX}${options.namespace}:revoked`;
		this.#encryption_key = options.key;

		if (options.max_token_length !== undefined) {
			if (
				!Number.isSafeInteger(options.max_token_length)
				|| options.max_token_length <= 0
			) {
				throw new TypeError(
					'Option max_token_length must be a positive safe integer.',
				);
			}

			this.#max_token_length = options.max_token_length;
		}

		this.#validator = options.validator;

		if (options.senml_key_map) {
			this.#cborEncoder = new CborEncoder({
				keyMap: options.senml_key_map,
			});
		}
	}

	/**
	 * Creates new token.
	 * @async
	 * @param data - Data to be stored in token.
	 * @param options -
	 * @param options.ttl - Time to live in **seconds**.
	 * @returns -
	 */
	async create(
		data: D,
		options: {
			/** Time to live in **seconds**. */
			ttl: number;
		},
	): Promise<Ecwt<D>> {
		if (!Number.isSafeInteger(options.ttl)) {
			throw new TypeError(
				`TTL value should be a safe integer, received ${options.ttl}.`,
			);
		}

		if (options.ttl > TTL_MAX) {
			throw new TypeError(
				`TTL value is too large. Maximum is ${TTL_MAX}, received ${options.ttl}.`,
			);
		}

		if (typeof this.#validator === 'function') {
			data = this.#validator(data);
		}

		const snowflake = await this.#snowflakeFactory.createSafe();
		const payload: v.InferOutput<typeof tokenSchema> = [
			snowflake.toBuffer(),
			options.ttl,
			data,
		];
		const token_raw = this.#cborEncoder
			? this.#cborEncoder.encode(payload)
			: cborEncode(payload);

		const token_encrypted = Buffer.concat([
			Buffer.from([0xf0]),
			aessiv(this.#encryption_key).encrypt(token_raw),
		]);
		// Use a conservative upper bound for the Base62 length before encoding.
		if (
			token_encrypted.byteLength * BASE62_EXPANSION_FACTOR
			> this.#max_token_length
		) {
			throw new RangeError(
				`Token exceeds maximum length of ${this.#max_token_length} characters.`,
			);
		}

		const token = base62.encode(token_encrypted);

		this.#setCache(token, {
			snowflake,
			ttl_initial: options.ttl,
			data,
		});

		return new Ecwt(this, {
			token,
			snowflake,
			ttl_initial: options.ttl,
			data,
		});
	}

	/**
	 * Sets data to cache.
	 * @param token - String representation of token.
	 * @param cache_value - Data to be stored in cache.
	 */
	#setCache(token: string, cache_value: LRUCacheValue<D>) {
		this.#lruCache?.set(token, cache_value, {
			ttl: cache_value.ttl_initial * 1000,
		});
	}

	async #decryptToken(token: string): Promise<LRUCacheValue<D>> {
		let cached_entry = this.#lruCache?.get(token);
		if (cached_entry) {
			return cached_entry;
		}

		try {
			const token_encrypted = Buffer.from(base62.decode(token));

			const token_raw =
				token_encrypted[0] === 0xf0
					? Buffer.from(
							aessiv(this.#encryption_key).decrypt(token_encrypted.subarray(1)),
						)
					: await evilcryptDecrypt(token_encrypted, this.#encryption_key);

			const payload = v.parse(
				tokenSchema,
				this.#cborEncoder
					? this.#cborEncoder.decode(token_raw)
					: cborDecode(token_raw),
			);

			const snowflake_buffer = payload[0];
			const ttl_initial = payload[1];
			const data_raw = payload[2];

			const snowflake = this.#snowflakeFactory.parse(snowflake_buffer);

			const data =
				typeof this.#validator === 'function'
					? this.#validator(data_raw)
					: (data_raw as D);

			cached_entry = {
				snowflake,
				ttl_initial,
				data,
			};
		} catch {
			throw new EcwtParseError();
		}

		this.#setCache(token, cached_entry);

		return cached_entry;
	}

	/**
	 * Parses token.
	 * @param token String representation of token.
	 * @returns -
	 */
	// oxlint-disable-next-line max-statements
	async verify(token: string): Promise<Ecwt<D>> {
		if (typeof token !== 'string') {
			throw new TypeError('Token must be a string.');
		}

		if (token.length > this.#max_token_length) {
			throw new EcwtParseError();
		}

		const { snowflake, ttl_initial, data } = await this.#decryptToken(token);

		const ecwt = new Ecwt(this, {
			token,
			snowflake,
			ttl_initial,
			data,
		});

		if (!Number.isSafeInteger(ttl_initial) || ttl_initial > TTL_MAX) {
			throw new EcwtInvalidError(ecwt);
		}

		if (snowflake.timestamp + ttl_initial * 1000 < Date.now()) {
			throw new EcwtExpiredError(ecwt);
		}

		if (this.#redisClient) {
			await this.#migrateExpired();

			if (await this.#redisClient.HEXISTS(this.#redis_key_revoked, ecwt.id)) {
				throw new EcwtRevokedError(ecwt);
			}
		}

		return ecwt;
	}

	/**
	 * Parses token without throwing errors.
	 * @param token - String representation of token.
	 * @returns Returns whether token was parsed and verified successfully and Ecwt if parsed.
	 */
	async safeVerify(token: string): Promise<
		| {
				success: true;
				ecwt: Ecwt<D>;
		  }
		| {
				success: false;
				ecwt: Ecwt<D> | null;
		  }
	> {
		try {
			const ecwt = await this.verify(token);

			return {
				success: true,
				ecwt,
			};
		} catch (error) {
			if (error instanceof EcwtParseError) {
				return {
					success: false,
					ecwt: null,
				};
			}

			if (
				error instanceof EcwtInvalidError
				|| error instanceof EcwtExpiredError
				|| error instanceof EcwtRevokedError
			) {
				return {
					success: false,
					ecwt: error.ecwt,
				};
			}

			throw error;
		}
	}

	/**
	 * Revokes token.
	 * @internal
	 * @param token_id -
	 * @param created_at_ms -
	 * @param ttl_initial -
	 * @returns -
	 */
	// eslint-disable-next-line unicorn/prefer-private-class-fields
	async _revoke(
		token_id: string,
		created_at_ms: number,
		ttl_initial: number,
	): Promise<void> {
		if (this.#redisClient) {
			await this.#migrateExpired();

			const expires_in_ms = created_at_ms + ttl_initial * 1000 - Date.now();
			if (expires_in_ms > 0) {
				await this.#redisClient
					.MULTI()
					.HSET(this.#redis_key_revoked, token_id, '')
					.HPEXPIRE(this.#redis_key_revoked, token_id, expires_in_ms)
					.EXEC();
			}
		} else {
			// oxlint-disable-next-line no-console
			console.warn(
				'[ecwt] Redis client is not provided. Tokens cannot be revoked.',
			);
		}
	}

	#migrated = false;

	async #migrateExpired() {
		if (this.#redisClient && !this.#migrated) {
			await this.#redisClient.EVAL(
				'local key = KEYS[1] if redis.call("TYPE", key)["ok"] ~= "zset" then return end local key_hash = key .. ":hash" local ts_now = tonumber(ARGV[1]) local cursor = "0" repeat local scan = redis.call("ZSCAN", key, cursor, "COUNT", 1000) cursor = scan[1] local items = scan[2] for i = 1, #items, 2 do local field = items[i] local expire_at = tonumber(items[i + 1]) local expire_in = expire_at and expire_at - ts_now if expire_in and expire_in > 0 then redis.call("HSET", key_hash, field, "") redis.call("HPEXPIRE", key_hash, expire_in, "FIELDS", 1, field) end end until cursor == "0" redis.call("DEL", key) if redis.call("EXISTS", key_hash) == 1 then redis.call("RENAME", key_hash, key) end',
				{
					keys: [this.#redis_key_revoked],
					arguments: [String(Date.now())],
				},
			);

			this.#migrated = true;
		}
	}

	/**
	 * Purges LRU cache.
	 * @internal
	 */
	// eslint-disable-next-line unicorn/prefer-private-class-fields
	_purgeCache(): void {
		this.#lruCache?.clear();
	}
}
