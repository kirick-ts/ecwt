"use strict";
//#region rolldown:runtime
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
	if (from && typeof from === "object" || typeof from === "function") for (var keys = __getOwnPropNames(from), i = 0, n = keys.length, key; i < n; i++) {
		key = keys[i];
		if (!__hasOwnProp.call(to, key) && key !== except) __defProp(to, key, {
			get: ((k) => from[k]).bind(null, key),
			enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
		});
	}
	return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", {
	value: mod,
	enumerable: true
}) : target, mod));

//#endregion
const cbor_x = __toESM(require("cbor-x"));
const evilcrypt = __toESM(require("evilcrypt"));
const base_x = __toESM(require("base-x"));

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
	ecwtFactory;
	ttl_initial;
	/**
	* @param {EcwtFactory} ecwtFactory -
	* @param {object} options -
	* @param {string} options.token String representation of token.
	* @param {Snowflake} options.snowflake -
	* @param {number | null} options.ttl_initial Time to live in seconds at the moment of token creation.
	* @param {D} options.data Data stored in token.
	*/
	constructor(ecwtFactory, options) {
		this.token = options.token;
		this.id = options.snowflake.toBase62();
		this.snowflake = options.snowflake;
		this.data = Object.freeze(options.data);
		this.ecwtFactory = ecwtFactory;
		this.ttl_initial = options.ttl_initial;
	}
	/**
	* Unix timestamp of token expiration in seconds.
	* @returns -
	*/
	get ts_expired() {
		if (this.ttl_initial === null) return null;
		return Math.floor(this.snowflake.timestamp / 1e3) + this.ttl_initial;
	}
	/**
	* Actual time to live in seconds.
	* @returns -
	*/
	getTTL() {
		if (this.ttl_initial === null) return null;
		return this.ttl_initial - Math.floor((Date.now() - this.snowflake.timestamp) / 1e3);
	}
	/**
	* Revokes token.
	* @returns {} -
	*/
	revoke() {
		return this.ecwtFactory._revoke(this.id, this.snowflake.timestamp, this.ttl_initial);
	}
};

//#endregion
//#region src/utils.ts
const base62 = (0, base_x.default)("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

//#endregion
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
//#region src/factory.ts
const REDIS_PREFIX = "@ecwt:";
var EcwtFactory = class {
	redisClient;
	lruCache;
	snowflakeFactory;
	redis_key_revoked;
	encryption_key;
	validator;
	cborEncoder = null;
	constructor({ redisClient, lruCache, snowflakeFactory, options }) {
		this.redisClient = redisClient;
		this.lruCache = lruCache;
		this.snowflakeFactory = snowflakeFactory;
		this.redis_key_revoked = `${REDIS_PREFIX}${options.namespace}:revoked`;
		this.encryption_key = options.key;
		this.validator = options.validator;
		if (options.senml_key_map) this.cborEncoder = new cbor_x.Encoder({ keyMap: options.senml_key_map });
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
		if (typeof this.validator === "function") data = this.validator(data);
		const ttl = options.ttl ?? null;
		const snowflake = await this.snowflakeFactory.createSafe();
		const payload = [
			snowflake.toBuffer(),
			ttl,
			data
		];
		const token_raw = this.cborEncoder ? this.cborEncoder.encode(payload) : (0, cbor_x.encode)(payload);
		const token_encrypted = await evilcrypt.v2.encrypt(token_raw, this.encryption_key);
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
		this.lruCache?.set(token, cache_value, cache_value.ttl_initial === null ? void 0 : { ttl: cache_value.ttl_initial * 1e3 });
	}
	/**
	* Parses token.
	* @param token String representation of token.
	* @returns -
	*/
	async verify(token) {
		if (typeof token !== "string") throw new TypeError("Token must be a string.");
		let snowflake;
		let ttl_initial;
		let data;
		const cached_entry = this.lruCache?.info(token);
		if (cached_entry === void 0) {
			const token_encrypted = Buffer.from(base62.decode(token));
			let token_raw;
			try {
				token_raw = await (0, evilcrypt.decrypt)(token_encrypted, this.encryption_key);
			} catch {
				throw new EcwtParseError();
			}
			const payload = this.cborEncoder ? this.cborEncoder.decode(token_raw) : (0, cbor_x.decode)(token_raw);
			const [snowflake_buffer] = payload;
			[, ttl_initial, data] = payload;
			snowflake = this.snowflakeFactory.parse(snowflake_buffer);
			if (typeof this.validator === "function") try {
				data = this.validator(data);
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
		if (this.redisClient) {
			const score = await this.redisClient.ZSCORE(this.redis_key_revoked, ecwt.id);
			if (score !== null) throw new EcwtRevokedError(ecwt);
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
	* @param token_id -
	* @param ts_ms_created -
	* @param ttl_initial -
	* @returns -
	*/
	async _revoke(token_id, ts_ms_created, ttl_initial) {
		if (this.redisClient) {
			ttl_initial ??= Number.MAX_SAFE_INTEGER;
			const ts_ms_expired = ts_ms_created + ttl_initial * 1e3;
			if (ts_ms_expired > Date.now()) await this.redisClient.MULTI().ZADD(this.redis_key_revoked, {
				score: ts_ms_expired,
				value: token_id
			}).ZREMRANGEBYSCORE(this.redis_key_revoked, "-inf", Date.now()).EXEC();
		} else console.warn("[ecwt] Redis client is not provided. Tokens cannot be revoked.");
	}
	/**
	* Purges LRU cache.
	* @returns {void} -
	*/
	_purgeCache() {
		this.lruCache?.clear();
	}
};

//#endregion
exports.Ecwt = Ecwt
exports.EcwtExpiredError = EcwtExpiredError
exports.EcwtFactory = EcwtFactory
exports.EcwtInvalidError = EcwtInvalidError
exports.EcwtParseError = EcwtParseError
exports.EcwtRevokedError = EcwtRevokedError