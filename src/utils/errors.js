
// @ts-check

export class InvalidPackageInstanceError extends TypeError {
	constructor(property, class_name, package_name) {
		super(`Value ${property} must be an instance of ${class_name} from package "${package_name}". That error is probably caused by two separate installations of "${package_name}". Please, make sure that "${package_name}" in your project is matches "peerDependencies" of "ecwt" package.`);
	}
}

/**
 * Error thrown when string token cannot be parsed to Ecwt.
 */
export class EcwtParseError extends Error {
	constructor() {
		super('Cannot parse data to Ecwt token.');
	}
}

/**
 * Error thrown when parsed Ecwt is invalid.
 */
export class EcwtInvalidError extends Error {
	constructor(ecwt) {
		super('Ecwt token is invalid.');

		this.ecwt = ecwt;
	}
}

/**
 * Error thrown when parsed Ecwt is expired.
 */
export class EcwtExpiredError extends EcwtInvalidError {
	constructor(ecwt) {
		super();

		this.ecwt = ecwt;
		this.message = 'Ecwt is expired.';
	}
}

/**
 * Error thrown when parsed Ecwt is revoked.
 */
export class EcwtRevokedError extends EcwtInvalidError {
	constructor(ecwt) {
		super();

		this.ecwt = ecwt;
		this.message = 'Ecwt is revoked.';
	}
}
