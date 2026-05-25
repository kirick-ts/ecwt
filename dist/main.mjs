import { Encoder, decode, encode } from "cbor-x";
import { decrypt, v2 } from "evilcrypt";
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
	* @param options.ttl_initial Time to live in seconds at the moment of token creation.
	* @param options.data Data stored in token.
	*/
	constructor(ecwtFactory, options) {
		this.token = options.token;
		this.id = options.snowflake.toBase62();
		this.snowflake = options.snowflake;
		this.data = Object.freeze(options.data);
		this.#ecwtFactory = ecwtFactory;
		this.#ttl_initial = options.ttl_initial;
	}
	/**
	* Unix timestamp of token expiration in seconds.
	* @returns -
	*/
	get ts_expired() {
		if (this.#ttl_initial === null) return null;
		return Math.floor(this.snowflake.timestamp / 1e3) + this.#ttl_initial;
	}
	/**
	* Actual time to live in seconds.
	* @returns -
	*/
	getTTL() {
		if (this.#ttl_initial === null) return null;
		return this.#ttl_initial - Math.floor((Date.now() - this.snowflake.timestamp) / 1e3);
	}
	/** Revokes token. */
	revoke() {
		return this.#ecwtFactory._revoke(this.id, this.snowflake.timestamp, this.#ttl_initial);
	}
};
//#endregion
//#region src/utils.ts
const base62 = basex("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
//#endregion
//#region src/factory.ts
const REDIS_PREFIX = "@ecwt:";
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
	* @param options.ttl - Time to live in seconds. If not defined, token will never expire.
	* @returns -
	*/
	async create(data, options = {}) {
		if (typeof this.#validator === "function") data = this.#validator(data);
		const ttl = options.ttl ?? null;
		const snowflake = await this.#snowflakeFactory.createSafe();
		const payload = [
			snowflake.toBuffer(),
			ttl,
			data
		];
		const token_raw = this.#cborEncoder ? this.#cborEncoder.encode(payload) : encode(payload);
		const token_encrypted = await v2.encrypt(token_raw, this.#encryption_key);
		const token = base62.encode(token_encrypted);
		this.setCache(token, {
			snowflake,
			ttl_initial: ttl,
			data
		});
		return new Ecwt(this, {
			token,
			snowflake,
			ttl_initial: ttl,
			data
		});
	}
	/**
	* Sets data to cache.
	* @param token - String representation of token.
	* @param cache_value - Data to be stored in cache.
	*/
	setCache(token, cache_value) {
		var _this$lruCache;
		(_this$lruCache = this.#lruCache) === null || _this$lruCache === void 0 || _this$lruCache.set(token, cache_value, cache_value.ttl_initial === null ? void 0 : { ttl: cache_value.ttl_initial * 1e3 });
	}
	/**
	* Parses token.
	* @param token String representation of token.
	* @returns -
	*/
	async verify(token) {
		var _this$lruCache2;
		if (typeof token !== "string") throw new TypeError("Token must be a string.");
		let snowflake;
		let ttl_initial;
		let data;
		const cached_entry = (_this$lruCache2 = this.#lruCache) === null || _this$lruCache2 === void 0 ? void 0 : _this$lruCache2.info(token);
		if (cached_entry === void 0) {
			const token_encrypted = Buffer.from(base62.decode(token));
			let token_raw;
			try {
				token_raw = await decrypt(token_encrypted, this.#encryption_key);
			} catch {
				throw new EcwtParseError();
			}
			const payload = this.#cborEncoder ? this.#cborEncoder.decode(token_raw) : decode(token_raw);
			const [snowflake_buffer] = payload;
			[, ttl_initial, data] = payload;
			snowflake = this.#snowflakeFactory.parse(snowflake_buffer);
			if (typeof this.#validator === "function") try {
				data = this.#validator(data);
			} catch {
				throw new EcwtParseError();
			}
			this.setCache(token, {
				snowflake,
				ttl_initial,
				data
			});
		} else ({snowflake, ttl_initial, data} = cached_entry.value);
		const ecwt = new Ecwt(this, {
			token,
			snowflake,
			ttl_initial,
			data
		});
		if (typeof ttl_initial === "number" && Number.isNaN(ttl_initial) !== true && snowflake.timestamp + ttl_initial * 1e3 < Date.now()) throw new EcwtExpiredError(ecwt);
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
		let ecwt = null;
		try {
			ecwt = await this.verify(token);
			return {
				success: true,
				ecwt
			};
		} catch (error) {
			if (error instanceof EcwtParseError) return {
				success: false,
				ecwt: null
			};
			if (error instanceof EcwtInvalidError) return {
				success: false,
				ecwt
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
			if (ttl_initial === null) await this.#redisClient.HSET(this.#redis_key_revoked, token_id, "");
			else {
				const expires_in_ms = created_at_ms + ttl_initial * 1e3 - Date.now();
				if (expires_in_ms > 0) await this.#redisClient.sendCommand([
					"HSET",
					this.#redis_key_revoked,
					token_id,
					"",
					"PX",
					String(expires_in_ms)
				]);
			}
		} else console.warn("[ecwt] Redis client is not provided. Tokens cannot be revoked.");
	}
	#migrated = false;
	async #migrateExpired() {
		if (this.#redisClient && !this.#migrated) {
			await this.#redisClient.EVAL("local key = KEYS[1] if redis.call(\"TYPE\", key)[\"ok\"] ~= \"zset\" then return end local key_hash = key .. \":hash\" local ts_now = tonumber(ARGV[1]) local cursor = \"0\" repeat local scan = redis.call(\"ZSCAN\", key, cursor, \"COUNT\", 1000) cursor = scan[1] local items = scan[2] for i = 1, #items, 2 do local field = items[i] local expire_at = tonumber(items[i + 1]) local expire_in = expire_at and expire_at - ts_now redis.call(\"HSET\", key_hash, field, \"\") if expire_in and expire_in > 0 then redis.call(\"HPEXPIRE\", key_hash, expire_in, \"FIELDS\", 1, field) end end until cursor == \"0\" redis.call(\"DEL\", key) redis.call(\"RENAME\", key_hash, key)", {
				keys: [this.#redis_key_revoked],
				arguments: [String(Date.now())]
			});
			this.#migrated = true;
		}
	}
	/**
	* @internal
	* Purges LRU cache.
	*/
	_purgeCache() {
		var _this$lruCache3;
		(_this$lruCache3 = this.#lruCache) === null || _this$lruCache3 === void 0 || _this$lruCache3.clear();
	}
};
//#endregion
export { Ecwt, EcwtExpiredError, EcwtFactory, EcwtInvalidError, EcwtParseError, EcwtRevokedError };
