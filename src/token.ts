import type { Snowflake } from '@kirick/snowflake';
import type { EcwtFactory } from './factory.js';
import type { ReadonlyDeep } from './utils/types.js';

export class Ecwt<
	const D extends Record<string, unknown> = Record<string, unknown>,
> {
	/** Token ID. */
	readonly id: string;
	/** Snowflake associated with token. */
	readonly snowflake: Snowflake;
	/** Time to live in **seconds** at the moment of token creation. */
	readonly ttl_initial: number;
	#ecwtFactory: EcwtFactory<D>;
	#token_raw: Uint8Array;

	/**
	 * @param ecwtFactory -
	 * @param token - String representation of token.
	 * @param token_raw - Byte array representation of token.
	 */
	constructor(
		ecwtFactory: EcwtFactory<D>,
		readonly token: string,
		token_raw: Uint8Array,
	) {
		const { snowflake_bytes, ttl_initial } =
			ecwtFactory._decodeToken(token_raw);
		const snowflake = ecwtFactory._snowflakeFactory.parse(snowflake_bytes);

		this.id = snowflake.toBase62();
		this.snowflake = snowflake;
		this.ttl_initial = ttl_initial;

		this.#ecwtFactory = ecwtFactory;
		this.#token_raw = token_raw;
	}

	/**
	 * Unix timestamp of token expiration in **seconds**.
	 * @returns -
	 */
	get ts_expired(): number {
		return Math.floor(this.snowflake.timestamp / 1000) + this.ttl_initial;
	}

	/**
	 * Actual time to live in **seconds**.
	 * @returns -
	 */
	get ttl(): number {
		return (
			this.ttl_initial
			- Math.floor((Date.now() - this.snowflake.timestamp) / 1000)
		);
	}

	get data(): ReadonlyDeep<D> {
		return this.#ecwtFactory._decodeToken(this.#token_raw)
			.data as ReadonlyDeep<D>;
	}

	/** Revokes token. */
	revoke(): Promise<void> {
		return this.#ecwtFactory._revoke(
			this.id,
			this.snowflake.timestamp,
			this.ttl_initial,
		);
	}
}
