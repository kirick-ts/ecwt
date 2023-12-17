
import { toSeconds } from './utils/time.js';

/**
 * @typedef {import('@kirick/snowflake/src/snowflake.js').Snowflake} Snowflake
 * @typedef {import('./factory.js').EcwtFactory} EcwtFactory
 */

export class Ecwt {
	#ecwtFactory;

	#token;
	#snowflake;
	#ttl_initial;
	#data;

	/**
	 * @param {EcwtFactory} ecwtFactory -
	 * @param {object} options -
	 * @param {string} options.token String representation of token.
	 * @param {Snowflake} options.snowflake -
	 * @param {number | null} options.ttl_initial Time to live in seconds at the moment of token creation.
	 * @param {object} options.data Data stored in token.
	 */
	constructor(
		ecwtFactory,
		{
			token,
			snowflake,
			ttl_initial,
			data,
		},
	) {
		this.#ecwtFactory = ecwtFactory;

		this.#token = token;
		this.#snowflake = snowflake;
		this.#ttl_initial = ttl_initial;
		this.#data = Object.freeze(data);
	}

	get token() {
		return this.#token;
	}

	get id() {
		return this.#snowflake.base62;
	}

	get snowflake() {
		return this.#snowflake;
	}

	get ts_expired() {
		if (this.#ttl_initial === null) {
			return Number.POSITIVE_INFINITY;
		}

		return toSeconds(this.#snowflake.timestamp) + this.#ttl_initial;
	}

	/**
	 * Time to live in seconds.
	 * @type {number}
	 * @readonly
	 */
	get ttl() {
		if (this.#ttl_initial === null) {
			return Number.POSITIVE_INFINITY;
		}

		return this.#ttl_initial - toSeconds(Date.now() - this.#snowflake.timestamp);
	}

	get data() {
		return this.#data;
	}

	/* async */ revoke() {
		return this.#ecwtFactory._revoke({
			token_id: this.id,
			ts_ms_created: this.#snowflake.timestamp,
			ttl_initial: this.#ttl_initial,
		});
	}
}
