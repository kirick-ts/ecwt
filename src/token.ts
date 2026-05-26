import type { Snowflake } from '@kirick/snowflake';
import type { EcwtFactory } from './factory.js';

export class Ecwt<
	const D extends Record<string, unknown> = Record<string, unknown>,
> {
	/** Token string representation. */
	readonly token: string;
	/** Token ID. */
	readonly id: string;
	/** Snowflake associated with token. */
	readonly snowflake: Snowflake;
	/** Data stored in token. */
	readonly data: Readonly<D>;
	#ecwtFactory: EcwtFactory<D>;
	#ttl_initial: number;

	/**
	 * @param ecwtFactory -
	 * @param options -
	 * @param options.token String representation of token.
	 * @param options.snowflake -
	 * @param options.ttl_initial Time to live in seconds at the moment of token creation.
	 * @param options.data Data stored in token.
	 */
	constructor(
		ecwtFactory: EcwtFactory<D>,
		options: {
			token: string;
			snowflake: Snowflake;
			ttl_initial: number;
			data: D;
		},
	) {
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
	get ts_expired(): number {
		return Math.floor(this.snowflake.timestamp / 1000) + this.#ttl_initial;
	}

	/**
	 * Actual time to live in seconds.
	 * @returns -
	 */
	getTTL(): number {
		return (
			this.#ttl_initial
			- Math.floor((Date.now() - this.snowflake.timestamp) / 1000)
		);
	}

	/** Revokes token. */
	revoke(): Promise<void> {
		return this.#ecwtFactory._revoke(
			this.id,
			this.snowflake.timestamp,
			this.#ttl_initial,
		);
	}
}
