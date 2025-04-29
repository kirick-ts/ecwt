import type { Ecwt } from './token.js';

/** Error thrown when string token cannot be parsed to Ecwt. */
export class EcwtParseError extends Error {
	constructor() {
		super('Cannot parse data to Ecwt token.');
	}
}

/** Error thrown when parsed Ecwt is invalid. */
export class EcwtInvalidError extends Error {
	message = 'Ecwt token is invalid.';

	constructor(readonly ecwt: Ecwt) {
		super();
	}
}

/** Error thrown when parsed Ecwt is expired. */
export class EcwtExpiredError extends EcwtInvalidError {
	message = 'Ecwt is expired.';
}

/** Error thrown when parsed Ecwt is revoked. */
export class EcwtRevokedError extends EcwtInvalidError {
	message = 'Ecwt is revoked.';
}
