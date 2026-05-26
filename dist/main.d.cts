import { Snowflake, SnowflakeFactory } from "@kirick/snowflake";
import { LRUCache } from "lru-cache";
import { RedisClientType, RedisFunctions, RedisModules, RedisScripts } from "redis";

//#region src/factory.d.ts
type LRUCacheValue = {
  snowflake: Snowflake;
  ttl_initial: number;
  data: Record<string, unknown>;
};
type RedisClient = RedisClientType<RedisModules, RedisFunctions, RedisScripts>;
type EcwtFactoryArguments<D extends Record<string, unknown>> = {
  /** RedisClient instance. If not provided, tokens can not be revoked and can not be checked for revocation. */redisClient?: RedisClient; /** LRUCache instance. If not provided, tokens will be decrypted every time they are verified. */
  lruCache?: LRUCache<string, LRUCacheValue>; /** SnowflakeFactory instance. Generates unique IDs for tokens. */
  snowflakeFactory: SnowflakeFactory;
  options: {
    /** Namespace for Redis keys. */namespace?: string; /** Encryption key, 64 bytes. */
    key: Buffer; /** Validator for token data. Should return validated value or throw an error. */
    validator?: (value: unknown) => D; /** Payload object keys mapped for their SenML keys. */
    senml_key_map?: Record<string, number>;
  };
};
declare class EcwtFactory<const D extends Record<string, unknown> = Record<string, unknown>> {
  #private;
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
  * @param options.ttl - Time to live in **seconds**.
  * @returns -
  */
  create(data: D, options: {
    /** Time to live in **seconds**. */ttl: number;
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
}
//#endregion
//#region src/token.d.ts
declare class Ecwt<const D extends Record<string, unknown> = Record<string, unknown>> {
  #private;
  /** Token string representation. */
  readonly token: string;
  /** Token ID. */
  readonly id: string;
  /** Snowflake associated with token. */
  readonly snowflake: Snowflake;
  /** Data stored in token. */
  readonly data: Readonly<D>;
  /**
  * @param ecwtFactory -
  * @param options -
  * @param options.token String representation of token.
  * @param options.snowflake -
  * @param options.ttl_initial Time to live in **seconds** at the moment of token creation.
  * @param options.data Data stored in token.
  */
  constructor(ecwtFactory: EcwtFactory<D>, options: {
    token: string;
    snowflake: Snowflake;
    ttl_initial: number;
    data: D;
  });
  /**
  * Unix timestamp of token expiration in **seconds**.
  * @returns -
  */
  get ts_expired(): number;
  /**
  * Actual time to live in **seconds**.
  * @returns -
  */
  getTTL(): number;
  /** Revokes token. */
  revoke(): Promise<void>;
}
//#endregion
//#region src/errors.d.ts
/** Error thrown when string token cannot be parsed to Ecwt. */
declare class EcwtParseError extends Error {
  constructor();
}
/** Error thrown when parsed Ecwt is invalid. */
declare class EcwtInvalidError<D extends Record<string, unknown>> extends Error {
  readonly ecwt: Ecwt<D>;
  override message: string;
  constructor(ecwt: Ecwt<D>);
}
/** Error thrown when parsed Ecwt is expired. */
declare class EcwtExpiredError<D extends Record<string, unknown>> extends EcwtInvalidError<D> {
  override message: string;
}
/** Error thrown when parsed Ecwt is revoked. */
declare class EcwtRevokedError<D extends Record<string, unknown>> extends EcwtInvalidError<D> {
  override message: string;
}
//#endregion
export { Ecwt, EcwtExpiredError, EcwtFactory, EcwtInvalidError, EcwtParseError, EcwtRevokedError };