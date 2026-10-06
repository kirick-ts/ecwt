import { aessiv } from "@noble/ciphers/aes.js";
import { Encoder, decode, encode } from "cbor-x";
import { decrypt } from "evilcrypt";
import * as v from "valibot";
import basex from "base-x";
//#region src/errors.ts
/** Error thrown when string token cannot be parsed to Ecwt. */
var EcwtParseError = class extends Error {
	constructor() {
		super("Cannot parse data to Ecwt token.");
	}
};
/** Error thrown when parsed Ecwt is invalid. */
var EcwtInvalidError = class extends Error {
	ecwt;
	message = "Ecwt token is invalid.";
	constructor(ecwt) {
		super();
		this.ecwt = ecwt;
	}
};
/** Error thrown when parsed Ecwt is expired. */
var EcwtExpiredError = class extends EcwtInvalidError {
	message = "Ecwt is expired.";
};
/** Error thrown when parsed Ecwt is revoked. */
var EcwtRevokedError = class extends EcwtInvalidError {
	message = "Ecwt is revoked.";
};
//#endregion
//#region src/utils.ts
const base62 = basex("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
/**
* Freezes own data properties and Map/Set entries recursively, without invoking getters.
* Values that reject freezing are retained; built-in and class internal state can remain mutable.
* @param object - Object to freeze in place.
* @returns The same object with recursively readonly properties.
*/
function deepFreeze(object) {
	const visited = /* @__PURE__ */ new WeakSet();
	/** @param value - Value to visit and freeze if supported. */
	function freeze(value) {
		if (value === null || typeof value !== "object" && typeof value !== "function" || visited.has(value)) return;
		visited.add(value);
		if (value instanceof Map) for (const [key, item] of value) {
			freeze(key);
			freeze(item);
		}
		else if (value instanceof Set) for (const item of value) freeze(item);
		for (const name of Reflect.ownKeys(value)) {
			const descriptor = Object.getOwnPropertyDescriptor(value, name);
			if (descriptor && "value" in descriptor) freeze(descriptor.value);
		}
		try {
			Object.freeze(value);
		} catch {}
	}
	freeze(object);
	return object;
}
//#endregion
//#region src/token.ts
var Ecwt = class {
	/** Token string representation. */
	token;
	/** Token ID. */
	id;
	/** Snowflake associated with token. */
	snowflake;
	/** Data stored in token. */
	data;
	#ecwtFactory;
	#ttl_initial;
	/**
	* @param ecwtFactory -
	* @param options -
	* @param options.token String representation of token.
	* @param options.snowflake -
	* @param options.ttl_initial Time to live in **seconds** at the moment of token creation.
	* @param options.data Data stored in token.
	*/
	constructor(ecwtFactory, options) {
		this.token = options.token;
		this.id = options.snowflake.toBase62();
		this.snowflake = options.snowflake;
		this.data = deepFreeze(options.data);
		this.#ecwtFactory = ecwtFactory;
		this.#ttl_initial = options.ttl_initial;
	}
	/**
	* Unix timestamp of token expiration in **seconds**.
	* @returns -
	*/
	get ts_expired() {
		return Math.floor(this.snowflake.timestamp / 1e3) + this.#ttl_initial;
	}
	/**
	* Actual time to live in **seconds**.
	* @returns -
	*/
	getTTL() {
		return this.#ttl_initial - Math.floor((Date.now() - this.snowflake.timestamp) / 1e3);
	}
	/** Revokes token. */
	revoke() {
		return this.#ecwtFactory._revoke(this.id, this.snowflake.timestamp, this.#ttl_initial);
	}
};
//#endregion
//#region src/factory.ts
const REDIS_PREFIX = "@ecwt:";
const TTL_MAX = 63072e3;
const tokenSchema = v.tuple([
	v.pipe(v.unknown(), v.check((value) => Buffer.isBuffer(value)), v.transform((value) => value)),
	v.number(),
	v.record(v.string(), v.unknown())
]);
var EcwtFactory = class {
	#redisClient;
	#lruCache;
	#snowflakeFactory;
	#redis_key_revoked;
	#encryption_key;
	#validator;
	#cborEncoder = null;
	constructor({ redisClient, lruCache, snowflakeFactory, options }) {
		this.#redisClient = redisClient;
		this.#lruCache = lruCache;
		this.#snowflakeFactory = snowflakeFactory;
		this.#redis_key_revoked = `${REDIS_PREFIX}${options.namespace}:revoked`;
		this.#encryption_key = options.key;
		this.#validator = options.validator;
		if (options.senml_key_map) this.#cborEncoder = new Encoder({ keyMap: options.senml_key_map });
	}
	/**
	* Creates new token.
	* @async
	* @param data - Data to be stored in token.
	* @param options -
	* @param options.ttl - Time to live in **seconds**.
	* @returns -
	*/
	async create(data, options) {
		if (!Number.isSafeInteger(options.ttl)) throw new TypeError(`TTL value should be a safe integer, received ${options.ttl}.`);
		if (options.ttl > 63072e3) throw new TypeError(`TTL value is too large. Maximum is ${TTL_MAX}, received ${options.ttl}.`);
		if (typeof this.#validator === "function") data = this.#validator(data);
		const snowflake = await this.#snowflakeFactory.createSafe();
		const payload = [
			snowflake.toBuffer(),
			options.ttl,
			data
		];
		const token_raw = this.#cborEncoder ? this.#cborEncoder.encode(payload) : encode(payload);
		const token_encrypted = Buffer.concat([Buffer.from([240]), aessiv(this.#encryption_key).encrypt(token_raw)]);
		const token = base62.encode(token_encrypted);
		this.#setCache(token, {
			snowflake,
			ttl_initial: options.ttl,
			data
		});
		return new Ecwt(this, {
			token,
			snowflake,
			ttl_initial: options.ttl,
			data
		});
	}
	/**
	* Sets data to cache.
	* @param token - String representation of token.
	* @param cache_value - Data to be stored in cache.
	*/
	#setCache(token, cache_value) {
		this.#lruCache?.set(token, cache_value, { ttl: cache_value.ttl_initial * 1e3 });
	}
	async #decryptToken(token) {
		let cached_entry = this.#lruCache?.get(token);
		if (cached_entry) return cached_entry;
		try {
			const token_encrypted = Buffer.from(base62.decode(token));
			const token_raw = token_encrypted[0] === 240 ? Buffer.from(aessiv(this.#encryption_key).decrypt(token_encrypted.subarray(1))) : await decrypt(token_encrypted, this.#encryption_key);
			const payload = v.parse(tokenSchema, this.#cborEncoder ? this.#cborEncoder.decode(token_raw) : decode(token_raw));
			const snowflake_buffer = payload[0];
			const ttl_initial = payload[1];
			const data_raw = payload[2];
			cached_entry = {
				snowflake: this.#snowflakeFactory.parse(snowflake_buffer),
				ttl_initial,
				data: typeof this.#validator === "function" ? this.#validator(data_raw) : data_raw
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
	async verify(token) {
		if (typeof token !== "string") throw new TypeError("Token must be a string.");
		const { snowflake, ttl_initial, data } = await this.#decryptToken(token);
		const ecwt = new Ecwt(this, {
			token,
			snowflake,
			ttl_initial,
			data
		});
		if (!Number.isSafeInteger(ttl_initial) || ttl_initial > 63072e3) throw new EcwtInvalidError(ecwt);
		if (snowflake.timestamp + ttl_initial * 1e3 < Date.now()) throw new EcwtExpiredError(ecwt);
		if (this.#redisClient) {
			await this.#migrateExpired();
			if (await this.#redisClient.HEXISTS(this.#redis_key_revoked, ecwt.id)) throw new EcwtRevokedError(ecwt);
		}
		return ecwt;
	}
	/**
	* Parses token without throwing errors.
	* @param token - String representation of token.
	* @returns Returns whether token was parsed and verified successfully and Ecwt if parsed.
	*/
	async safeVerify(token) {
		try {
			return {
				success: true,
				ecwt: await this.verify(token)
			};
		} catch (error) {
			if (error instanceof EcwtParseError) return {
				success: false,
				ecwt: null
			};
			if (error instanceof EcwtInvalidError || error instanceof EcwtExpiredError || error instanceof EcwtRevokedError) return {
				success: false,
				ecwt: error.ecwt
			};
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
	async _revoke(token_id, created_at_ms, ttl_initial) {
		if (this.#redisClient) {
			await this.#migrateExpired();
			const expires_in_ms = created_at_ms + ttl_initial * 1e3 - Date.now();
			if (expires_in_ms > 0) await this.#redisClient.MULTI().HSET(this.#redis_key_revoked, token_id, "").HPEXPIRE(this.#redis_key_revoked, token_id, expires_in_ms).EXEC();
		} else console.warn("[ecwt] Redis client is not provided. Tokens cannot be revoked.");
	}
	#migrated = false;
	async #migrateExpired() {
		if (this.#redisClient && !this.#migrated) {
			await this.#redisClient.EVAL("local key = KEYS[1] if redis.call(\"TYPE\", key)[\"ok\"] ~= \"zset\" then return end local key_hash = key .. \":hash\" local ts_now = tonumber(ARGV[1]) local cursor = \"0\" repeat local scan = redis.call(\"ZSCAN\", key, cursor, \"COUNT\", 1000) cursor = scan[1] local items = scan[2] for i = 1, #items, 2 do local field = items[i] local expire_at = tonumber(items[i + 1]) local expire_in = expire_at and expire_at - ts_now if expire_in and expire_in > 0 then redis.call(\"HSET\", key_hash, field, \"\") redis.call(\"HPEXPIRE\", key_hash, expire_in, \"FIELDS\", 1, field) end end until cursor == \"0\" redis.call(\"DEL\", key) if redis.call(\"EXISTS\", key_hash) == 1 then redis.call(\"RENAME\", key_hash, key) end", {
				keys: [this.#redis_key_revoked],
				arguments: [String(Date.now())]
			});
			this.#migrated = true;
		}
	}
	/**
	* Purges LRU cache.
	* @internal
	*/
	_purgeCache() {
		this.#lruCache?.clear();
	}
};
//#endregion
export { Ecwt, EcwtExpiredError, EcwtFactory, EcwtInvalidError, EcwtParseError, EcwtRevokedError };
