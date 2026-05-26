import type { Ecwt } from './token.js';

/** Error thrown when string token cannot be parsed to Ecwt. */
export class EcwtParseError extends Error {
	constructor() {
		super('Cannot parse data to Ecwt token.');
	}
}

/** Error thrown when parsed Ecwt is invalid. */
export class EcwtInvalidError<D extends Record<string, unknown>> extends Error {
	override message = 'Ecwt token is invalid.';

	constructor(readonly ecwt: Ecwt<D>) {
		super();
	}
}

/** Error thrown when parsed Ecwt is expired. */
export class EcwtExpiredError<
	D extends Record<string, unknown>,
> extends EcwtInvalidError<D> {
	override message = 'Ecwt is expired.';
}

/** Error thrown when parsed Ecwt is revoked. */
export class EcwtRevokedError<
	D extends Record<string, unknown>,
> extends EcwtInvalidError<D> {
	override message = 'Ecwt is revoked.';
}
