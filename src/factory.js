
/**
 * @typedef {import('@kirick/snowflake').Snowflake} Snowflake
 */
/**
 * @typedef {object} CacheValue
 * @property {Snowflake} snowflake -
 * @property {number | null} ttl_initial -
 * @property {Record<string, any>} data -
 */

import { SnowflakeFactory }       from '@kirick/snowflake';
import {
	Encoder as CborEncoder,
	encode as cborEncode,
	decode as cborDecode,
}                                 from 'cbor-x';
import {
	decrypt as evilcryptDecrypt,
	v2 as evilcryptV2,
}                                 from 'evilcrypt';
import { LRUCache }               from 'lru-cache';
import { Ecwt }                   from './token.js';
import { base62 }                 from './utils/base62.js';
import {
	InvalidPackageInstanceError,
	EcwtInvalidError,
	EcwtExpiredError,
	EcwtRevokedError,
    EcwtParseError,
}                                 from './utils/errors.js';

const REDIS_PREFIX = '@ecwt:';

/**
 * @template {Record<string, any>} [D=Record<string, any>]
 */
export class EcwtFactory {
	#redisClient;
	#lruCache;
	#snowflakeFactory;
	#redis_key_revoked;
	#encryption_key;
	#validator;
	/** @type {CborEncoder | null} */
	#cborEncoder = null;

	/**
	 * @param {object} param0 -
	 * @param {import('redis').RedisClientType<import('redis').RedisModules, import('redis').RedisFunctions, import('redis').RedisScripts>} [param0.redisClient] RedisClient instance. If not provided, tokens will not be revoked and cannot be checked for revocation.
	 * @param {LRUCache<string, CacheValue>} [param0.lruCache] LRUCache instance. If not provided, tokens will be decrypted every time they are verified.
	 * @param {SnowflakeFactory} param0.snowflakeFactory SnowflakeFactory instance.
	 * @param {object} param0.options -
	 * @param {string} [param0.options.namespace] Namespace for Redis keys.
	 * @param {Buffer} param0.options.key Encryption key, 64 bytes
	 * @param {(value: any) => any} [param0.options.validator] Validator for token data. Should return validated value or throw an error.
	 * @param {Record<string, number>} [param0.options.senml_key_map] Payload object keys mapped for their SenML keys.
	 */
	constructor({
		redisClient,
		lruCache,
		snowflakeFactory,
		options: {
			namespace,
			key,
			validator,
			senml_key_map,
		},
	}) {
		this.#redisClient = redisClient;

		if (
			lruCache !== undefined
			&& lruCache instanceof LRUCache !== true
		) {
			throw new InvalidPackageInstanceError(
				'lruCache',
				'LRUCache',
				'lru-cache',
			);
		}

		this.#lruCache = lruCache;

		if (snowflakeFactory instanceof SnowflakeFactory !== true) {
			throw new InvalidPackageInstanceError(
				'snowflakeFactory',
				'SnowflakeFactory',
				'@kirick/snowflake',
			);
		}

		this.#snowflakeFactory = snowflakeFactory;

		this.#redis_key_revoked = `${REDIS_PREFIX}${namespace}:revoked`;

		this.#encryption_key = key;

		this.#validator = validator;

		if (senml_key_map) {
			this.#cborEncoder = new CborEncoder({
				keyMap: senml_key_map,
			});
		}
	}

	/**
	 * Creates new token.
	 * @async
	 * @param {D} data Data to be stored in token.
	 * @param {object} [options] -
	 * @param {number | null} [options.ttl] Time to live in seconds. By default, token will never expire.
	 * @returns {Promise<Ecwt>} -
	 */
	async create(
		data,
		{
			ttl = null,
		} = {},
	) {
		if (typeof this.#validator === 'function') {
			data = this.#validator(data);
		}

		if (
			typeof ttl !== 'number'
			&& Number.isNaN(ttl) !== true
			&& ttl !== null
		) {
			throw new TypeError('TTL must be a number or null.');
		}

		const snowflake = await this.#snowflakeFactory.createSafe();

		const payload = [
			snowflake.toBuffer(),
			ttl,
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

		this.#setCache(
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
	 * @param {string} token String representation of token.
	 * @param {CacheValue} cache_value Data to be stored in cache.
	 */
	#setCache(token, cache_value) {
		this.#lruCache?.set(
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
	 * @async
	 * @param {string} token String representation of token.
	 * @returns {Promise<Ecwt>} -
	 */
	async verify(token) {
		if (typeof token !== 'string') {
			throw new TypeError('Token must be a string.');
		}

		let snowflake;
		let ttl_initial;
		let data;

		const cached_entry = this.#lruCache?.info(token);
		// token is not cached
		if (cached_entry === undefined) {
			const token_encrypted = Buffer.from(
				base62.decode(token),
			);

			let token_raw;
			try {
				token_raw = await evilcryptDecrypt(
					token_encrypted,
					this.#encryption_key,
				);
			}
			catch {
				throw new EcwtParseError();
			}

			const payload = this.#cborEncoder
				? this.#cborEncoder.decode(token_raw)
				: cborDecode(token_raw);

			const [ snowflake_buffer ] = payload;
			[
				,
				ttl_initial,
				data,
			] = payload;

			snowflake = this.#snowflakeFactory.parse(snowflake_buffer);

			if (typeof this.#validator === 'function') {
				try {
					data = this.#validator(data);
				}
				catch {
					throw new EcwtParseError();
				}
			}

			this.#setCache(
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

		if (this.#redisClient) {
			const score = await this.#redisClient.ZSCORE(
				this.#redis_key_revoked,
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
	 * @async
	 * @param {string} token String representation of token.
	 * @returns {Promise<{ success: true, ecwt: Ecwt } | { success: false, ecwt: Ecwt | null }>} Returns whether token was parsed and verified successfully and Ecwt if parsed.
	 */
	async safeVerify(token) {
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
	 * @async
	 * @param {object} options -
	 * @param {string} options.token_id -
	 * @param {number} options.ts_ms_created -
	 * @param {number | null} options.ttl_initial -
	 * @returns {Promise<void>} -
	 */
	async _revoke({
		token_id,
		ts_ms_created,
		ttl_initial,
	}) {
		if (this.#redisClient) {
			ttl_initial ??= Number.MAX_SAFE_INTEGER;

			const ts_ms_expired = ts_ms_created + (ttl_initial * 1000);
			if (ts_ms_expired > Date.now()) {
				// await this.#redisClient.sendCommand([
				// 	'ZADD',
				// 	this.#redis_keys.revoked,
				// 	String(ts_ms_expired),
				// 	token_id,
				// ]);
				await this.#redisClient.MULTI()
					.addCommand([
						'ZADD',
						this.#redis_key_revoked,
						String(ts_ms_expired),
						token_id,
					])
					.addCommand([
						'ZREMRANGEBYSCORE',
						this.#redis_key_revoked,
						'-inf',
						String(Date.now()),
					])
					.EXEC();
			}
		}
		else {
			console.warn('[ecwt] Redis client is not provided. Tokens cannot be revoked.');
		}
	}

	/**
	 * Purges cache.
	 * @private
	 * @returns {void} -
	 */
	_purgeCache() {
		this.#lruCache?.clear();
	}
}
