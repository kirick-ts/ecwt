import { Snowflake, SnowflakeFactory } from "@kirick/snowflake";
import { LRUCache } from "lru-cache";
import { RedisClientType, RedisFunctions, RedisModules, RedisScripts } from "redis";
//#region src/factory.d.ts
type LRUCacheValue<D extends Record<string, unknown> = Record<string, unknown>> = {
  snowflake: Snowflake;
  ttl_initial: number;
  data: D;
};
type RedisClient = RedisClientType<RedisModules, RedisFunctions, RedisScripts>;
type EcwtFactoryArguments<D extends Record<string, unknown>> = {
  /** RedisClient instance. If not provided, tokens can not be revoked and can not be checked for revocation. */
  redisClient?: RedisClient;
  /** SnowflakeFactory instance. Generates unique IDs for tokens. */
  snowflakeFactory: SnowflakeFactory;
  options: {
    /** Namespace for Redis keys. */
    namespace?: string;
    /** Encryption key, 64 bytes. */
    key: Buffer;
    /**
     * Options for a private LRU cache. If not provided, tokens will be decrypted every time they are verified.
     * @see https://npmx.dev/package/lru-cache#user-content-usage
     */
    lru_cache?: LRUCache.Options<string, LRUCacheValue<D>, unknown>;
    /** Maximum serialized token length in Base62 characters. Defaults to 4000. */
    max_token_length?: number;
    /** Validator for token data. Should return validated value or throw an error. */
    validator?: (value: unknown) => D;
    /** Payload object keys mapped for their SenML keys. */
    senml_key_map?: Record<string, number>;
  };
};
export declare class EcwtFactory<const D extends Record<string, unknown> = Record<string, unknown>> {
  #private;
  constructor({ redisClient, snowflakeFactory, options }: EcwtFactoryArguments<D>);
  /**
   * Creates new token.
   * @async
   * @param data - Data to be stored in token.
   * @param options -
   * @param options.ttl - Time to live in **seconds**.
   * @returns -
   */
  create(data: D, options: {
    /** Time to live in **seconds**. */
    ttl: number;
  }): Promise<Ecwt<D>>;
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
   * @internal
   * @param token_id -
   * @param created_at_ms -
   * @param ttl_initial -
   * @returns -
   */
  _revoke(token_id: string, created_at_ms: number, ttl_initial: number): Promise<void>;
  /**
   * Purges LRU cache.
   * @internal
   */
  _purgeCache(): void;
}
//#endregion
//#region src/utils/types.d.ts
type Primitive = null | undefined | string | number | boolean | symbol | bigint;
type BuiltIns = Primitive | void | Date | RegExp;
type HasMultipleCallSignatures<T extends (...arguments_: any[]) => unknown> = T extends {
  (...arguments_: infer A): unknown;
  (...arguments_: infer B): unknown;
} ? B extends A ? A extends B ? false : true : true : false;
type ReadonlyDeep<T> = T extends BuiltIns ? T : T extends (new (...arguments_: any[]) => unknown) ? T : T extends ((...arguments_: any[]) => unknown) ? {} extends _ReadonlyObjectDeep<T> ? T : HasMultipleCallSignatures<T> extends true ? T : ((...arguments_: Parameters<T>) => ReturnType<T>) & _ReadonlyObjectDeep<T> : T extends Readonly<ReadonlyMap<infer KeyType, infer ValueType>> ? ReadonlyMapDeep<KeyType, ValueType> : T extends Readonly<ReadonlySet<infer ItemType>> ? ReadonlySetDeep<ItemType> : T extends readonly [] | readonly [...never[]] ? readonly [] : T extends readonly [infer U, ...infer V] ? readonly [ReadonlyDeep<U>, ...ReadonlyDeep<V>] : T extends readonly [...infer U, infer V] ? readonly [...ReadonlyDeep<U>, ReadonlyDeep<V>] : T extends ReadonlyArray<infer ItemType> ? ReadonlyArray<ReadonlyDeep<ItemType>> : T extends object ? _ReadonlyObjectDeep<T> : unknown;
type ReadonlyMapDeep<KeyType, ValueType> = {} & Readonly<ReadonlyMap<ReadonlyDeep<KeyType>, ReadonlyDeep<ValueType>>>;
type ReadonlySetDeep<ItemType> = {} & Readonly<ReadonlySet<ReadonlyDeep<ItemType>>>;
type _ReadonlyObjectDeep<ObjectType extends object> = { readonly [KeyType in keyof ObjectType]: ReadonlyDeep<ObjectType[KeyType]>; };
//#endregion
//#region src/token.d.ts
export declare class Ecwt<const D extends Record<string, unknown> = Record<string, unknown>> {
  #private;
  /** Token string representation. */
  readonly token: string;
  /** Token ID. */
  readonly id: string;
  /** Snowflake associated with token. */
  readonly snowflake: Snowflake;
  /** Data stored in token. */
  readonly data: ReadonlyDeep<D>;
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
export declare class EcwtParseError extends Error {
  constructor();
}
/** Error thrown when parsed Ecwt is invalid. */
export declare class EcwtInvalidError<D extends Record<string, unknown>> extends Error {
  readonly ecwt: Ecwt<D>;
  override message: string;
  constructor(ecwt: Ecwt<D>);
}
/** Error thrown when parsed Ecwt is expired. */
export declare class EcwtExpiredError<D extends Record<string, unknown>> extends EcwtInvalidError<D> {
  override message: string;
}
/** Error thrown when parsed Ecwt is revoked. */
export declare class EcwtRevokedError<D extends Record<string, unknown>> extends EcwtInvalidError<D> {
  override message: string;
}
//#endregion