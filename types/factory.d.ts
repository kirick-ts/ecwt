export class EcwtFactory {
    /**
     *
     * @param {object} param0 -
     * @param {import('redis').RedisClientType} [param0.redisClient] RedisClient instance. If not provided, tokens will not be revoked and cannot be checked for revocation.
     * @param {LRUCache<string, CacheValue>} [param0.lruCache] LRUCache instance. If not provided, tokens will be decrypted every time they are verified.
     * @param {SnowflakeFactory} param0.snowflakeFactory SnowflakeFactory instance.
     * @param {object} param0.options -
     * @param {string} [param0.options.namespace] Namespace for Redis keys.
     * @param {Buffer} param0.options.key Encryption key, 64 bytes
     * @param {(value: any) => any} [param0.options.validator] Validator for token data. Should return validated value or throw an error.
     * @param {Record<string, number>} [param0.options.senml_key_map] Payload object keys mapped for their SenML keys.
     */
    constructor({ redisClient, lruCache, snowflakeFactory, options: { namespace, key, validator, senml_key_map, }, }: {
        redisClient?: import("redis").RedisClientType;
        lruCache?: LRUCache<string, CacheValue>;
        snowflakeFactory: SnowflakeFactory;
        options: {
            namespace?: string;
            key: Buffer;
            validator?: (value: any) => any;
            senml_key_map?: Record<string, number>;
        };
    });
    /**
     * Creates new token.
     * @async
     * @param {object} data Data to be stored in token.
     * @param {object} [options] -
     * @param {number | null} [options.ttl] Time to live in seconds. By default, token will never expire.
     * @returns {Promise<Ecwt>} -
     */
    create(data: object, { ttl, }?: {
        ttl?: number | null;
    }): Promise<Ecwt>;
    /**
     * Parses token.
     * @async
     * @param {string} token String representation of token.
     * @returns {Promise<Ecwt>} -
     */
    verify(token: string): Promise<Ecwt>;
    /**
     * Parses token without throwing errors.
     * @async
     * @param {string} token String representation of token.
     * @returns {Promise<{ success: true, ecwt: Ecwt } | { success: false, ecwt: Ecwt | null }>} Returns whether token was parsed and verified successfully and Ecwt if parsed.
     */
    safeVerify(token: string): Promise<{
        success: true;
        ecwt: Ecwt;
    } | {
        success: false;
        ecwt: Ecwt | null;
    }>;
    /**
     * Revokes token.
     * @async
     * @param {object} options -
     * @param {string} options.token_id -
     * @param {number} options.ts_ms_created -
     * @param {number | null} options.ttl_initial -
     * @returns {Promise<void>} -
     */
    _revoke({ token_id, ts_ms_created, ttl_initial, }: {
        token_id: string;
        ts_ms_created: number;
        ttl_initial: number | null;
    }): Promise<void>;
    /**
     * Purges cache.
     * @private
     * @returns {void} -
     */
    private _purgeCache;
    #private;
}
export type Snowflake = import("@kirick/snowflake").Snowflake;
export type CacheValue = {
    /**
     * -
     */
    snowflake: Snowflake;
    /**
     * -
     */
    ttl_initial: number;
    /**
     * -
     */
    data: Record<string, any>;
};
import { Ecwt } from './token.js';
import { LRUCache } from 'lru-cache';
import { SnowflakeFactory } from '@kirick/snowflake';
