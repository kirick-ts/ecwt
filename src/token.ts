import type { Snowflake } from '@kirick/snowflake';
import type { EcwtFactory } from './factory.js';

export class Ecwt<const D extends Record<string, unknown> = Record<string, unknown>> {
	/** Token string representation. */
	readonly token: string;
	/** Token ID. */
	readonly id: string;
	/** Snowflake associated with token. */
	readonly snowflake: Snowflake;
	/** Data stored in token. */
	readonly data: Readonly<D>;
	private ecwtFactory: EcwtFactory;
	private ttl_initial: number | null;

	/**
	 * @param {EcwtFactory} ecwtFactory -
	 * @param {object} options -
	 * @param {string} options.token String representation of token.
	 * @param {Snowflake} options.snowflake -
	 * @param {number | null} options.ttl_initial Time to live in seconds at the moment of token creation.
	 * @param {D} options.data Data stored in token.
	 */
	constructor(
		ecwtFactory: EcwtFactory,
		options: {
			token: string,
			snowflake: Snowflake,
			ttl_initial: number | null,
			data: D,
		},
	) {
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
	get ts_expired(): number | null {
		if (this.ttl_initial === null) {
			return null;
		}

		return Math.floor(this.snowflake.timestamp / 1000) + this.ttl_initial;
	}

	/**
	 * Actual time to live in seconds.
	 * @returns -
	 */
	getTTL(): number | null {
		if (this.ttl_initial === null) {
			return null;
		}

		return this.ttl_initial - Math.floor((Date.now() - this.snowflake.timestamp) / 1000);
	}

	/**
	 * Revokes token.
	 * @returns {} -
	 */
	revoke(): Promise<void> {
		// @ts-expect-error Accessing private method
		return this.ecwtFactory._revoke(
			this.id,
			this.snowflake.timestamp,
			this.ttl_initial,
		);
	}
}
