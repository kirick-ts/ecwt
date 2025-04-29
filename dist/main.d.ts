import { Snowflake, SnowflakeFactory } from "@kirick/snowflake";
import { LRUCache } from "lru-cache";
import { RedisClientType, RedisFunctions, RedisModules, RedisScripts } from "redis";

//#region src/token.d.ts
declare class Ecwt<D extends Record<string, unknown> = Record<string, unknown>> {
  /** Token string representation. */
  readonly token: string;
  /** Token ID. */
  readonly id: string;
  /** Snowflake associated with token. */
  readonly snowflake: Snowflake;
  /** Data stored in token. */
  readonly data: Readonly<D>;
  private ecwtFactory;
  private ttl_initial;
  /**
  * @param {EcwtFactory} ecwtFactory -
  * @param {object} options -
  * @param {string} options.token String representation of token.
  * @param {Snowflake} options.snowflake -
  * @param {number | null} options.ttl_initial Time to live in seconds at the moment of token creation.
  * @param {D} options.data Data stored in token.
  */
  constructor(ecwtFactory: EcwtFactory, options: {
    token: string;
    snowflake: Snowflake;
    ttl_initial: number | null;
    data: D;
  });
  /**
  * Unix timestamp of token expiration in seconds.
  * @returns -
  */
  get ts_expired(): number | null;
  /**
  * Actual time to live in seconds.
  * @returns -
  */
  getTTL(): number | null;
  /**
  * Revokes token.
  * @returns {} -
  */
  revoke(): Promise<void>;
} //#endregion
//#region src/factory.d.ts
type LRUCacheValue = {
  snowflake: Snowflake;
  ttl_initial: number | null;
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
declare class EcwtFactory<D extends Record<string, unknown> = Record<string, unknown>> {
  private redisClient;
  private lruCache;
  private snowflakeFactory;
  private redis_key_revoked;
  private encryption_key;
  private validator;
  private cborEncoder;
  constructor({
    redisClient,
    lruCache,
    snowflakeFactory,
    options
  }: EcwtFactoryArguments<D>);
  /**
  * Creates new token.
  * @async
  * @param data - Data to be stored in token.
  * @param options -
  * @param options.ttl - Time to live in seconds. If not defined, token will never expire.
  * @returns -
  */
  create(data: D, options?: {
    /** Time to live in seconds. If not defined, token will never expire. */
    ttl?: number;
  }): Promise<Ecwt<D>>;
  /**
  * Sets data to cache.
  * @param token - String representation of token.
  * @param cache_value - Data to be stored in cache.
  */
  private setCache;
  /**
  * Parses token.
  * @param token String representation of token.
  * @returns -
  */
  verify(token: string): Promise<Ecwt<D>>;
  /**
  * Parses token without throwing errors.
  * @param token - String representation of token.
  * @returns Returns whether token was parsed and verified successfully and Ecwt if parsed.
  */
  safeVerify(token: string): Promise<{
    success: true;
    ecwt: Ecwt<D>;
  } | {
    success: false;
    ecwt: Ecwt<D> | null;
  }>;
  /**
  * Revokes token.
  * @param token_id -
  * @param ts_ms_created -
  * @param ttl_initial -
  * @returns -
  */
  private _revoke;
  /**
  * Purges LRU cache.
  * @returns {void} -
  */
  private _purgeCache;
} //#endregion
//#region src/errors.d.ts
/** Error thrown when string token cannot be parsed to Ecwt. */
declare class EcwtParseError extends Error {
  constructor();
}

/** Error thrown when parsed Ecwt is invalid. */
declare class EcwtInvalidError extends Error {
  readonly ecwt: Ecwt;
  message: string;
  constructor(ecwt: Ecwt);
}

/** Error thrown when parsed Ecwt is expired. */
declare class EcwtExpiredError extends EcwtInvalidError {
  message: string;
}

/** Error thrown when parsed Ecwt is revoked. */
declare class EcwtRevokedError extends EcwtInvalidError {
  message: string;
}

//#endregion
export { Ecwt, EcwtExpiredError, EcwtFactory, EcwtInvalidError, EcwtParseError, EcwtRevokedError };