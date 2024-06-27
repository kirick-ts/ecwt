/**
 * @typedef {import('@kirick/snowflake').Snowflake} Snowflake
 * @typedef {import('./factory.js').EcwtFactory} EcwtFactory
 */
export class Ecwt {
    /**
     * @param {EcwtFactory} ecwtFactory -
     * @param {object} options -
     * @param {string} options.token String representation of token.
     * @param {Snowflake} options.snowflake -
     * @param {number?} options.ttl_initial Time to live in seconds at the moment of token creation.
     * @param {object} options.data Data stored in token.
     */
    constructor(ecwtFactory: EcwtFactory, { token, snowflake, ttl_initial, data, }: {
        token: string;
        snowflake: Snowflake;
        ttl_initial: number | null;
        data: object;
    });
    /**
     * Token string representation.
     * @type {string}
     * @readonly
     */
    readonly token: string;
    /**
     * Token ID.
     * @type {string}
     * @readonly
     */
    readonly id: string;
    /**
     * Snowflake associated with token.
     * @type {Snowflake}
     * @readonly
     */
    readonly snowflake: Snowflake;
    /**
     * Timestamp when token expires in seconds.
     * @type {number?}
     * @readonly
     */
    readonly ts_expired: number | null;
    /**
     * Data stored in token.
     * @type {{ [key: string]: any }}
     * @readonly
     */
    readonly data: {
        [key: string]: any;
    };
    /**
     * Actual time to live in seconds.
     * @returns {number | null} -
     */
    getTTL(): number | null;
    /**
     * Revokes token.
     * @returns {Promise<void>} -
     */
    revoke(): Promise<void>;
    #private;
}
export type Snowflake = import("@kirick/snowflake").Snowflake;
export type EcwtFactory = import("./factory.js").EcwtFactory;
