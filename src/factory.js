
import { SnowflakeFactory }       from '@kirick/snowflake';
import {
	Encoder as CborEncoder,
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
	EcwtInvalidError,
	EcwtExpiredError,
	EcwtRevokedError,
    EcwtParseError }              from './utils/errors.js';

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

	#validator;
	#cborEncoder;

	/**
	 *
	 * @param {object} param0 -
	 * @param {import('redis').RedisClientType} [param0.redisClient] RedisClient instance. If not provided, tokens will not be revoked and cannot be checked for revocation.
	 * @param {LRUCache} [param0.lruCache] LRUCache instance. If not provided, tokens will be decrypted every time they are verified.
	 * @param {SnowflakeFactory} param0.snowflakeFactory SnowflakeFactory instance.
	 * @param {object} param0.options -
	 * @param {string} [param0.options.namespace] Namespace for Redis keys.
	 * @param {Buffer} param0.options.key Encryption key, 64 bytes
	 * @param {(value: any) => any} [param0.options.validator] Validator for token data. Should return validated value or throw an error.
	 * @param {{ [key: string]: number }} [param0.options.senml_key_map] Payload object keys mapped for their SenML keys.
	 */
	constructor({
		redisClient = null,
		lruCache = null,
		snowflakeFactory,
		options: {
			namespace = null,
			key,
			validator,
			senml_key_map,
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

			const [
				snowflake_buffer,
			] = payload;
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
	 * Parses token without throwing errors.
	 * @async
	 * @param {string} token String representation of token.
	 * @returns {Promise<{ success: boolean, ecwt: Ecwt | null }>} Returns whether token was parsed and verified successfully and Ecwt if parsed.
	 */
	async safeVerify(token) {
		let ecwt;
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
	 * @param {number} options.ttl_initial -
	 * @returns {Promise<void>} -
	 */
	async _revoke({
		token_id,
		ts_ms_created,
		ttl_initial,
	}) {
		if (this.#redisClient) {
			ttl_initial = ttl_initial ?? Number.MAX_SAFE_INTEGER;

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
