
import { SnowflakeFactory }       from '@kirick/snowflake';
import {
	encode as cborEncode,
	decode as cborDecode }        from 'cbor-x';
import {
	decrypt as evilcryptDecrypt,
	v2 as evilcryptV2          }  from 'evilcrypt';
import { LRUCache }               from 'lru-cache';
import { createClient }           from 'redis';
import { Ecwt }                   from './token.js';
import { base62 }                 from './utils/base62.js';
import {
	InvalidPackageInstanceError,
	EcwtExpiredError,
	EcwtRevokedError }            from './utils/errors.js';

const REDIS_PREFIX = '@ecwt:';

// eslint-disable-next-line jsdoc/require-jsdoc
function getAllKeysList(value) {
	const keys = [];
	// eslint-disable-next-line guard-for-in
	for (const key in value) {
		keys.push(key);
	}
	return keys.sort().join(',');
}

const redisClient = createClient();
const redis_client_constructor_name = redisClient.constructor.name;
const redis_client_keys = getAllKeysList(redisClient);

export class EcwtFactory {
	#redisClient;
	#lruCache;
	#snowflakeFactory;

	#redis_keys = {};
	#encryption_key;

	#schema;
	#schema_keys_sorted;

	/**
	 *
	 * @param {object} param0 -
	 * @param {import('redis').RedisClientType} [param0.redisClient] RedisClient instance. If not provided, tokens will not be revoked and cannot be checked for revocation.
	 * @param {LRUCache} [param0.lruCache] LRUCache instance. If not provided, tokens will be decrypted every time they are verified.
	 * @param {SnowflakeFactory} param0.snowflakeFactory SnowflakeFactory instance.
	 * @param {object} param0.options -
	 * @param {string} [param0.options.namespace] Namespace for Redis keys.
	 * @param {Buffer} param0.options.key Encryption key, 64 bytes
	 * @param {{ [key: string]: (value: any) => boolean }} param0.options.schema Schema for token data. Each property is a validator function that returns true if value is valid.
	 */
	constructor({
		redisClient = null,
		lruCache = null,
		snowflakeFactory,
		options: {
			namespace = null,
			key,
			schema = {},
		},
	}) {
		if (
			redisClient !== null
			&& (
				redisClient.constructor.name !== redis_client_constructor_name
				|| getAllKeysList(redisClient) !== redis_client_keys
			)
		) {
			throw new InvalidPackageInstanceError(
				'redisClient',
				'Commander extends RedisClient',
				'redis',
			);
		}
		this.#redisClient = redisClient;

		if (
			lruCache !== null
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

		this.#redis_keys.revoked = `${REDIS_PREFIX}${namespace}:revoked`;

		this.#encryption_key = key;

		this.#schema = schema;
		this.#schema_keys_sorted = Object.keys(schema).sort();
	}

	/**
	 * Creates new token.
	 * @async
	 * @param {object} data Data to be stored in token.
	 * @param {object} [options] -
	 * @param {number} [options.ttl] Time to live in seconds. By default, token will never expire.
	 * @returns {Promise<Ecwt>} -
	 */
	async create(
		data,
		{
			ttl,
		} = {},
	) {
		const payload = [];
		for (const key of this.#schema_keys_sorted) {
			const value = data[key];
			const validator = this.#schema[key];

			if (
				typeof validator === 'function'
				&& validator(value) !== true
			) {
				throw new TypeError(`Value "${value}" of property "${key}" is invalid.`);
			}

			payload.push(value);
		}

		if (
			(
				typeof ttl !== 'number'
				&& Number.isNaN(ttl) !== true
			)
			|| ttl === Number.POSITIVE_INFINITY
		) {
			ttl = null;
		}

		const snowflake = await this.#snowflakeFactory.createSafe();

		const token_raw = cborEncode([
			snowflake.buffer,
			ttl,
			payload,
		]);

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

	#setCache(token, data) {
		this.#lruCache?.set(
			token,
			data,
			{
				ttl: data.ttl * 1000,
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
		// token is cached
		if (cached_entry === undefined) {
			const token_encrypted = Buffer.from(
				base62.decode(token),
			);

			const token_raw = await evilcryptDecrypt(
				token_encrypted,
				this.#encryption_key,
			);

			const [
				snowflake_buffer,
				_ttl_initial,
				payload,
			] = cborDecode(token_raw);

			snowflake = this.#snowflakeFactory.parse(snowflake_buffer);
			ttl_initial = _ttl_initial;

			data = {};
			for (const [ index, key ] of this.#schema_keys_sorted.entries()) {
				data[key] = payload[index];
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
				this.#redis_keys.revoked,
				ecwt.id,
			);
			if (score !== null) {
				throw new EcwtRevokedError(ecwt);
			}
		}

		return ecwt;
	}

	/**
	 * Revokes token.
	 * @async
	 * @param {object} options -
	 * @param {string} options.token_id -
	 * @param {number} options.ts_ms_created -
	 * @param {number} options.ttl_initial -
	 * @returns {Promise<void>} -
	 */
	async _revoke({
		token_id,
		ts_ms_created,
		ttl_initial,
	}) {
		if (this.#redisClient) {
			const ts_ms_expired = ts_ms_created + (ttl_initial * 1000);
			if (ts_ms_expired > Date.now()) {
				await this.#redisClient.sendCommand([
					'ZADD',
					this.#redis_keys.revoked,
					String(ts_ms_expired),
					token_id,
				]);
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
