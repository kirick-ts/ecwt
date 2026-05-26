import type { Snowflake, SnowflakeFactory } from '@kirick/snowflake';
import {
	Encoder as CborEncoder,
	decode as cborDecode,
	encode as cborEncode,
} from 'cbor-x';
import { decrypt as evilcryptDecrypt, v2 as evilcryptV2 } from 'evilcrypt';
import type { LRUCache } from 'lru-cache';
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

export type LRUCacheValue = {
	snowflake: Snowflake;
	ttl_initial: number;
	data: Record<string, unknown>;
};
type RedisClient = RedisClientType<RedisModules, RedisFunctions, RedisScripts>;
type EcwtFactoryArguments<D extends Record<string, unknown>> = {
	/** RedisClient instance. If not provided, tokens can not be revoked and can not be checked for revocation. */
	redisClient?: RedisClient;
	/** LRUCache instance. If not provided, tokens will be decrypted every time they are verified. */
	lruCache?: LRUCache<string, LRUCacheValue>;
	/** SnowflakeFactory instance. Generates unique IDs for tokens. */
	snowflakeFactory: SnowflakeFactory;
	options: {
		/** Namespace for Redis keys. */
		namespace?: string;
		/** Encryption key, 64 bytes. */
		key: Buffer;
		/** Validator for token data. Should return validated value or throw an error. */
		validator?: (value: unknown) => D;
		/** Payload object keys mapped for their SenML keys. */
		senml_key_map?: Record<string, number>;
	};
};

const REDIS_PREFIX = '@ecwt:';
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
	#lruCache: LRUCache<string, LRUCacheValue> | undefined;
	#snowflakeFactory: SnowflakeFactory;
	#redis_key_revoked: string;
	#encryption_key: Buffer;
	#validator: ((value: unknown) => D) | undefined;
	#cborEncoder: CborEncoder | null = null;

	constructor({
		redisClient,
		lruCache,
		snowflakeFactory,
		options,
	}: EcwtFactoryArguments<D>) {
		this.#redisClient = redisClient;
		this.#lruCache = lruCache;
		this.#snowflakeFactory = snowflakeFactory;

		this.#redis_key_revoked = `${REDIS_PREFIX}${options.namespace}:revoked`;
		this.#encryption_key = options.key;
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
	 * @param options.ttl - Time to live in seconds. If not defined, token will never expire.
	 * @returns -
	 */
	async create(
		data: D,
		options: {
			/** Time to live in seconds. If not defined, token will never expire. */
			ttl: number;
		},
	): Promise<Ecwt<D>> {
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

		const token_encrypted = await evilcryptV2.encrypt(
			token_raw,
			this.#encryption_key,
		);

		const token = base62.encode(token_encrypted);

		this.setCache(token, {
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
	private setCache(token: string, cache_value: LRUCacheValue) {
		this.#lruCache?.set(token, cache_value, {
			ttl: cache_value.ttl_initial * 1000,
		});
	}

	/**
	 * Parses token.
	 * @param token String representation of token.
	 * @returns -
	 */
	async verify(token: string): Promise<Ecwt<D>> {
		if (typeof token !== 'string') {
			throw new TypeError('Token must be a string.');
		}

		let snowflake: Snowflake;
		let ttl_initial: number;
		let data: D;

		const cached_entry = this.#lruCache?.info(token);
		// token is not cached
		if (cached_entry === undefined) {
			const token_encrypted = Buffer.from(base62.decode(token));

			let token_raw;
			try {
				token_raw = await evilcryptDecrypt(
					token_encrypted,
					this.#encryption_key,
				);
			} catch {
				throw new EcwtParseError();
			}

			const payload = v.parse(
				tokenSchema,
				this.#cborEncoder
					? this.#cborEncoder.decode(token_raw)
					: cborDecode(token_raw),
			);

			const snowflake_buffer = payload[0];
			ttl_initial = payload[1];
			const data_raw = payload[2];

			snowflake = this.#snowflakeFactory.parse(snowflake_buffer);

			if (typeof this.#validator === 'function') {
				try {
					data = this.#validator(data_raw);
				} catch {
					throw new EcwtParseError();
				}
			} else {
				data = data_raw as D;
			}

			this.setCache(token, {
				snowflake,
				ttl_initial,
				data,
			});
		} else {
			snowflake = cached_entry.value.snowflake;
			ttl_initial = cached_entry.value.ttl_initial;
			data = cached_entry.value.data as D;
		}

		// console.log('snowflake', snowflake);
		// console.log('ttl', ttl);
		// console.log('data', data);

		const ecwt = new Ecwt(this, {
			token,
			snowflake,
			ttl_initial,
			data,
		});

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
		let ecwt = null;
		try {
			ecwt = await this.verify(token);

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

			if (error instanceof EcwtInvalidError) {
				return {
					success: false,
					ecwt,
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
	 * @internal
	 * Purges LRU cache.
	 */
	_purgeCache() {
		this.#lruCache?.clear();
	}
}
