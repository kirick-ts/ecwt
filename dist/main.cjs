Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
//#region \0rolldown/runtime.js
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
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule || !__hasOwnProp.call(mod, "default") ? __defProp(target, "default", {
	value: mod,
	enumerable: true
}) : target, mod));
//#endregion
let _noble_ciphers_aes_js = require("@noble/ciphers/aes.js");
let cbor_x = require("cbor-x");
let lru_cache = require("lru-cache");
let valibot = require("valibot");
valibot = __toESM(valibot, 1);
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
//#region node_modules/base-x/src/esm/index.js
function base(ALPHABET) {
	if (ALPHABET.length >= 255) throw new TypeError("Alphabet too long");
	const BASE_MAP = /* @__PURE__ */ new Uint8Array(256);
	for (let j = 0; j < BASE_MAP.length; j++) BASE_MAP[j] = 255;
	for (let i = 0; i < ALPHABET.length; i++) {
		const x = ALPHABET.charAt(i);
		const xc = x.charCodeAt(0);
		if (BASE_MAP[xc] !== 255) throw new TypeError(x + " is ambiguous");
		BASE_MAP[xc] = i;
	}
	const BASE = ALPHABET.length;
	const LEADER = ALPHABET.charAt(0);
	const FACTOR = Math.log(BASE) / Math.log(256);
	const iFACTOR = Math.log(256) / Math.log(BASE);
	function encode(source) {
		if (source instanceof Uint8Array) {} else if (ArrayBuffer.isView(source)) source = new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
		else if (Array.isArray(source)) source = Uint8Array.from(source);
		if (!(source instanceof Uint8Array)) throw new TypeError("Expected Uint8Array");
		if (source.length === 0) return "";
		let zeroes = 0;
		let length = 0;
		let pbegin = 0;
		const pend = source.length;
		while (pbegin !== pend && source[pbegin] === 0) {
			pbegin++;
			zeroes++;
		}
		const size = (pend - pbegin) * iFACTOR + 1 >>> 0;
		const b58 = new Uint8Array(size);
		while (pbegin !== pend) {
			let carry = source[pbegin];
			let i = 0;
			for (let it1 = size - 1; (carry !== 0 || i < length) && it1 !== -1; it1--, i++) {
				carry += 256 * b58[it1] >>> 0;
				b58[it1] = carry % BASE >>> 0;
				carry = carry / BASE >>> 0;
			}
			if (carry !== 0) throw new Error("Non-zero carry");
			length = i;
			pbegin++;
		}
		let it2 = size - length;
		while (it2 !== size && b58[it2] === 0) it2++;
		let str = LEADER.repeat(zeroes);
		for (; it2 < size; ++it2) str += ALPHABET.charAt(b58[it2]);
		return str;
	}
	function decodeUnsafe(source) {
		if (typeof source !== "string") throw new TypeError("Expected String");
		if (source.length === 0) return /* @__PURE__ */ new Uint8Array();
		let psz = 0;
		let zeroes = 0;
		let length = 0;
		while (source[psz] === LEADER) {
			zeroes++;
			psz++;
		}
		const size = (source.length - psz) * FACTOR + 1 >>> 0;
		const b256 = new Uint8Array(size);
		while (psz < source.length) {
			const charCode = source.charCodeAt(psz);
			if (charCode > 255) return;
			let carry = BASE_MAP[charCode];
			if (carry === 255) return;
			let i = 0;
			for (let it3 = size - 1; (carry !== 0 || i < length) && it3 !== -1; it3--, i++) {
				carry += BASE * b256[it3] >>> 0;
				b256[it3] = carry % 256 >>> 0;
				carry = carry / 256 >>> 0;
			}
			if (carry !== 0) throw new Error("Non-zero carry");
			length = i;
			psz++;
		}
		let it4 = size - length;
		while (it4 !== size && b256[it4] === 0) it4++;
		const vch = new Uint8Array(zeroes + (size - it4));
		let j = zeroes;
		while (it4 !== size) vch[j++] = b256[it4++];
		return vch;
	}
	function decode(string) {
		const buffer = decodeUnsafe(string);
		if (buffer) return buffer;
		throw new Error("Non-base" + BASE + " character");
	}
	return {
		encode,
		decodeUnsafe,
		decode
	};
}
//#endregion
//#region src/utils.ts
const base62 = base("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
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
const BASE62_EXPANSION_FACTOR = 8 / Math.log2(62);
const TTL_MAX = 63072e3;
const sharedCborEncoder = new cbor_x.Encoder({
	useRecords: false,
	tagUint8Array: false
});
const tokenSchema = valibot.tuple([
	valibot.instance(Uint8Array),
	valibot.number(),
	valibot.record(valibot.string(), valibot.unknown())
]);
var EcwtFactory = class {
	#redisClient;
	#lruCache;
	#snowflakeFactory;
	#redis_key_revoked;
	#encryption_key;
	#max_token_length = 4e3;
	#validator;
	#cborEncoder = sharedCborEncoder;
	constructor({ redisClient, snowflakeFactory, options }) {
		this.#redisClient = redisClient;
		this.#lruCache = options.lru_cache ? new lru_cache.LRUCache(options.lru_cache) : void 0;
		this.#snowflakeFactory = snowflakeFactory;
		this.#redis_key_revoked = `${REDIS_PREFIX}${options.namespace}:revoked`;
		this.#encryption_key = options.key;
		if (options.max_token_length !== void 0) {
			if (!Number.isSafeInteger(options.max_token_length) || options.max_token_length <= 0) throw new TypeError("Option max_token_length must be a positive safe integer.");
			this.#max_token_length = options.max_token_length;
		}
		this.#validator = options.validator;
		if (options.senml_key_map) this.#cborEncoder = new cbor_x.Encoder({
			useRecords: false,
			tagUint8Array: false,
			keyMap: options.senml_key_map
		});
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
			snowflake.toUint8Array(),
			options.ttl,
			data
		];
		const token_raw = this.#cborEncoder.encode(payload);
		const ciphertext = (0, _noble_ciphers_aes_js.aessiv)(this.#encryption_key).encrypt(token_raw);
		const token_encrypted = new Uint8Array(ciphertext.byteLength + 1);
		token_encrypted[0] = 240;
		token_encrypted.set(ciphertext, 1);
		if (token_encrypted.byteLength * BASE62_EXPANSION_FACTOR > this.#max_token_length) throw new RangeError(`Token exceeds maximum length of ${this.#max_token_length} characters.`);
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
	#decryptToken(token) {
		let cached_entry = this.#lruCache?.get(token);
		if (cached_entry) return cached_entry;
		try {
			const token_encrypted = base62.decode(token);
			if (token_encrypted[0] !== 240) throw new EcwtParseError();
			const token_raw = (0, _noble_ciphers_aes_js.aessiv)(this.#encryption_key).decrypt(token_encrypted.subarray(1));
			const payload = valibot.parse(tokenSchema, this.#cborEncoder.decode(token_raw));
			const snowflake_bytes = payload[0];
			const ttl_initial = payload[1];
			const data_raw = payload[2];
			cached_entry = {
				snowflake: this.#snowflakeFactory.parse(snowflake_bytes),
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
		if (token.length > this.#max_token_length) throw new EcwtParseError();
		const { snowflake, ttl_initial, data } = this.#decryptToken(token);
		const ecwt = new Ecwt(this, {
			token,
			snowflake,
			ttl_initial,
			data
		});
		if (!Number.isSafeInteger(ttl_initial) || ttl_initial > 63072e3) throw new EcwtInvalidError(ecwt);
		if (snowflake.timestamp + ttl_initial * 1e3 < Date.now()) throw new EcwtExpiredError(ecwt);
		if (this.#redisClient && await this.#redisClient.HEXISTS(this.#redis_key_revoked, ecwt.id)) throw new EcwtRevokedError(ecwt);
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
			const expires_in_ms = created_at_ms + ttl_initial * 1e3 - Date.now();
			if (expires_in_ms > 0) await this.#redisClient.MULTI().HSET(this.#redis_key_revoked, token_id, "").HPEXPIRE(this.#redis_key_revoked, token_id, expires_in_ms).EXEC();
		} else console.warn("[ecwt] Redis client is not provided. Tokens cannot be revoked.");
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
exports.Ecwt = Ecwt;
exports.EcwtExpiredError = EcwtExpiredError;
exports.EcwtFactory = EcwtFactory;
exports.EcwtInvalidError = EcwtInvalidError;
exports.EcwtParseError = EcwtParseError;
exports.EcwtRevokedError = EcwtRevokedError;
