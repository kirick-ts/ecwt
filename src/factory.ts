import type {
	Snowflake,
	SnowflakeFactory,
} from '@kirick/snowflake';
import {
	Encoder as CborEncoder,
	encode as cborEncode,
	decode as cborDecode,
} from 'cbor-x';
import {
	decrypt as evilcryptDecrypt,
	v2 as evilcryptV2,
} from 'evilcrypt';
import type { LRUCache } from 'lru-cache';
import type {
	RedisClientType,
	RedisFunctions,
	RedisModules,
	RedisScripts,
} from 'redis';
import { Ecwt } from './token.js';
import { base62 } from './utils.js';
import {
	EcwtInvalidError,
	EcwtExpiredError,
	EcwtRevokedError,
	EcwtParseError,
} from './errors.js';

export type LRUCacheValue = {
	snowflake: Snowflake,
	ttl_initial: number | null,
	data: Record<string, unknown>,
};
type RedisClient = RedisClientType<RedisModules, RedisFunctions, RedisScripts>;
type EcwtFactoryArguments<D extends Record<string, unknown>> = {
	/** RedisClient instance. If not provided, tokens can not be revoked and can not be checked for revocation. */
	redisClient?: RedisClient,
	/** LRUCache instance. If not provided, tokens will be decrypted every time they are verified. */
	lruCache?: LRUCache<string, LRUCacheValue>,
	/** SnowflakeFactory instance. Generates unique IDs for tokens. */
	snowflakeFactory: SnowflakeFactory,
	options: {
		/** Namespace for Redis keys. */
		namespace?: string,
		/** Encryption key, 64 bytes. */
		key: Buffer,
		/** Validator for token data. Should return validated value or throw an error. */
		validator?: (value: unknown) => D,
		/** Payload object keys mapped for their SenML keys. */
		senml_key_map?: Record<string, number>,
	},
};

const REDIS_PREFIX = '@ecwt:';

export class EcwtFactory<const D extends Record<string, unknown> = Record<string, unknown>> {
	private redisClient: RedisClient | undefined;
	private lruCache: LRUCache<string, LRUCacheValue> | undefined;
	private snowflakeFactory: SnowflakeFactory;
	private redis_key_revoked: string;
	private encryption_key: Buffer;
	private validator: ((value: unknown) => D) | undefined;
	private cborEncoder: CborEncoder | null = null;

	constructor({
		redisClient,
		lruCache,
		snowflakeFactory,
		options,
	}: EcwtFactoryArguments<D>) {
		this.redisClient = redisClient;
		this.lruCache = lruCache;
		this.snowflakeFactory = snowflakeFactory;

		this.redis_key_revoked = `${REDIS_PREFIX}${options.namespace}:revoked`;
		this.encryption_key = options.key;
		this.validator = options.validator;

		if (options.senml_key_map) {
			this.cborEncoder = new CborEncoder({
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
			ttl?: number,
		} = {},
	): Promise<Ecwt<D>> {
		if (typeof this.validator === 'function') {
			data = this.validator(data);
		}

		const ttl = options.ttl ?? null;
		const snowflake = await this.snowflakeFactory.createSafe();
		const payload = [
			snowflake.toBuffer(),
			ttl,
			data,
		];
		const token_raw = this.cborEncoder
			? this.cborEncoder.encode(payload)
			: cborEncode(payload);

		const token_encrypted = await evilcryptV2.encrypt(
			token_raw,
			this.encryption_key,
		);

		const token = base62.encode(token_encrypted);

		this.setCache(
			token,
			{
				snowflake,
				ttl_initial: ttl,
				data,
			},
		);

		return new Ecwt(
			this,
			{
				token,
				snowflake,
				ttl_initial: ttl,
				data,
			},
		);
	}

	/**
	 * Sets data to cache.
	 * @param token - String representation of token.
	 * @param cache_value - Data to be stored in cache.
	 */
	private setCache(token: string, cache_value: LRUCacheValue) {
		this.lruCache?.set(
			token,
			cache_value,
			cache_value.ttl_initial === null
				? undefined
				: {
					ttl: cache_value.ttl_initial * 1000,
				},
		);
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

		let snowflake;
		let ttl_initial;
		let data;

		const cached_entry = this.lruCache?.info(token);
		// token is not cached
		if (cached_entry === undefined) {
			const token_encrypted = Buffer.from(
				base62.decode(token),
			);

			let token_raw;
			try {
				token_raw = await evilcryptDecrypt(
					token_encrypted,
					this.encryption_key,
				);
			}
			catch {
				throw new EcwtParseError();
			}

			const payload = this.cborEncoder
				? this.cborEncoder.decode(token_raw)
				: cborDecode(token_raw);

			const [ snowflake_buffer ] = payload;
			[
				,
				ttl_initial,
				data,
			] = payload;

			snowflake = this.snowflakeFactory.parse(snowflake_buffer);

			if (typeof this.validator === 'function') {
				try {
					data = this.validator(data);
				}
				catch {
					throw new EcwtParseError();
				}
			}

			this.setCache(
				token,
				{
					snowflake,
					ttl_initial,
					data,
				},
			);
		}
		else {
			({
				snowflake,
				ttl_initial,
				data,
			} = cached_entry.value);
		}

		// console.log('snowflake', snowflake);
		// console.log('ttl', ttl);
		// console.log('data', data);

		const ecwt = new Ecwt(
			this,
			{
				token,
				snowflake,
				ttl_initial,
				data,
			},
		);

		if (
			typeof ttl_initial === 'number'
			&& Number.isNaN(ttl_initial) !== true
			&& snowflake.timestamp + (ttl_initial * 1000) < Date.now()
		) {
			throw new EcwtExpiredError(ecwt);
		}

		if (this.redisClient) {
			const score = await this.redisClient.ZSCORE(
				this.redis_key_revoked,
				ecwt.id,
			);
			if (score !== null) {
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
		{
			success: true,
			ecwt: Ecwt<D>,
		}
		| {
			success: false,
			ecwt: Ecwt<D> | null,
		}
	> {
		let ecwt = null;
		try {
			ecwt = await this.verify(token);

			return {
				success: true,
				ecwt,
			};
		}
		catch (error) {
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
	 * @param token_id -
	 * @param ts_ms_created -
	 * @param ttl_initial -
	 * @returns -
	 */
	private async _revoke(
		token_id: string,
		ts_ms_created: number,
		ttl_initial: number | null,
	) {
		if (this.redisClient) {
			ttl_initial ??= Number.MAX_SAFE_INTEGER;

			const ts_ms_expired = ts_ms_created + (ttl_initial * 1000);
			if (ts_ms_expired > Date.now()) {
				await this.redisClient.MULTI()
					.ZADD(
						this.redis_key_revoked,
						{
							score: ts_ms_expired,
							value: token_id,
						},
					)
					.ZREMRANGEBYSCORE(
						this.redis_key_revoked,
						'-inf',
						Date.now(),
					)
					.EXEC();
			}
		}
		else {
			// eslint-disable-next-line no-console
			console.warn('[ecwt] Redis client is not provided. Tokens cannot be revoked.');
		}
	}

	/**
	 * Purges LRU cache.
	 * @returns {void} -
	 */
	private _purgeCache() {
		this.lruCache?.clear();
	}
}
