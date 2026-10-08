import type { SnowflakeFactory } from '@kirick/snowflake';
import { aessiv } from '@noble/ciphers/aes.js';
import { Encoder as CborEncoder } from 'cbor-x';
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
		key: Uint8Array;
		/**
		 * Options for a private LRU cache. If not provided, tokens will be decrypted every time they are verified.
		 * @see https://npmx.dev/package/lru-cache#user-content-usage
		 */
		lru_cache?: LRUCache.Options<string, Uint8Array, unknown>;
		/** Maximum serialized token length in Base62 characters. Defaults to 4000. */
		max_token_length?: number;
		/** Validator for token data. Should return validated value or throw an error. */
		validator?: (value: D) => D;
		/** Payload object keys mapped for their SenML keys. */
		senml_key_map?: Record<string, number>;
	};
};

const REDIS_PREFIX = '@ecwt:';
const BASE62_EXPANSION_FACTOR = 8 / Math.log2(62);
export const TTL_MAX: number = 2 * 365 * 24 * 60 * 60;

const sharedCborEncoder = new CborEncoder({
	useRecords: false,
	tagUint8Array: false,
	copyBuffers: true,
});

const tokenSchema = v.tuple([
	v.instance(Uint8Array<ArrayBufferLike>),
	v.number(),
	v.record(v.string(), v.unknown()),
]);

export class EcwtFactory<
	const D extends Record<string, unknown> = Record<string, unknown>,
> {
	#redisClient: RedisClient | undefined;
	#lruCache: LRUCache<string, Uint8Array> | undefined;
	/** @internal */
	// eslint-disable-next-line unicorn/prefer-private-class-fields
	_snowflakeFactory: SnowflakeFactory;
	#redis_key_revoked: string;
	#encryption_key: Uint8Array;
	#max_token_length = 4000;
	#validator: ((value: D) => D) | undefined;
	#cborEncoder: CborEncoder = sharedCborEncoder;

	constructor({
		redisClient,
		snowflakeFactory,
		options,
	}: EcwtFactoryArguments<D>) {
		this.#redisClient = redisClient;
		this.#lruCache = options.lru_cache
			? new LRUCache(options.lru_cache)
			: undefined;
		this._snowflakeFactory = snowflakeFactory;

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
				useRecords: false,
				tagUint8Array: false,
				copyBuffers: true,
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

		const snowflake = await this._snowflakeFactory.createSafe();
		const payload: v.InferOutput<typeof tokenSchema> = [
			snowflake.toUint8Array(),
			options.ttl,
			data,
		];
		const encoded = this.#cborEncoder.encode(payload);
		const token_raw = new Uint8Array(
			encoded.buffer,
			encoded.byteOffset,
			encoded.byteLength,
		);

		const ciphertext = aessiv(this.#encryption_key).encrypt(token_raw);
		const token_encrypted = new Uint8Array(ciphertext.byteLength + 1);
		token_encrypted[0] = 0xf0;
		token_encrypted.set(ciphertext, 1);
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
		const ecwt = new Ecwt(this, token, token_raw);

		this.#setCache(token, token_raw, ecwt);

		return ecwt;
	}

	/**
	 * Sets data to cache.
	 * @param token - String representation of token.
	 * @param token_raw - Raw token data to be stored in cache.
	 * @param ecwt - Ecwt instance to use for TTL calculation.
	 */
	#setCache(token: string, token_raw: Uint8Array, ecwt: Ecwt<D>) {
		this.#lruCache?.set(token, token_raw, {
			ttl: ecwt.ttl * 1000,
		});
	}

	#decryptToken(token: string): [is_cached: boolean, token_raw: Uint8Array] {
		const token_raw = this.#lruCache?.get(token);
		if (token_raw) {
			return [true, token_raw];
		}

		try {
			const token_encrypted = base62.decode(token);

			if (token_encrypted[0] !== 0xf0) {
				throw new EcwtParseError();
			}

			return [
				false,
				aessiv(this.#encryption_key).decrypt(token_encrypted.subarray(1)),
			];
		} catch {
			throw new EcwtParseError();
		}
	}

	/**
	 * @internal
	 * @param token_raw - Raw token data to be decoded.
	 */
	// eslint-disable-next-line unicorn/prefer-private-class-fields
	_decodeToken(token_raw: Uint8Array): {
		snowflake_bytes: Uint8Array;
		ttl_initial: number;
		data: D;
	} {
		const payload = v.parse(tokenSchema, this.#cborEncoder.decode(token_raw));

		const snowflake_bytes = payload[0];
		const ttl_initial = payload[1];
		const data_raw = payload[2] as D;

		const data =
			typeof this.#validator === 'function'
				? this.#validator(data_raw)
				: data_raw;

		return {
			snowflake_bytes,
			ttl_initial,
			data,
		};
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

		const [is_cached, token_raw] = this.#decryptToken(token);
		let ecwt: Ecwt<D>;
		try {
			ecwt = new Ecwt(this, token, token_raw);
		} catch {
			throw new EcwtParseError();
		}

		if (!is_cached) {
			this.#setCache(token, token_raw, ecwt);
		}

		if (!Number.isSafeInteger(ecwt.ttl_initial) || ecwt.ttl_initial > TTL_MAX) {
			throw new EcwtInvalidError(ecwt);
		}

		if (ecwt.snowflake.timestamp + ecwt.ttl_initial * 1000 < Date.now()) {
			throw new EcwtExpiredError(ecwt);
		}

		if (
			this.#redisClient
			&& (await this.#redisClient.HEXISTS(this.#redis_key_revoked, ecwt.id))
		) {
			throw new EcwtRevokedError(ecwt);
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

	/**
	 * Purges LRU cache.
	 * @internal
	 */
	// eslint-disable-next-line unicorn/prefer-private-class-fields
	_purgeCache(): void {
		this.#lruCache?.clear();
	}
}
