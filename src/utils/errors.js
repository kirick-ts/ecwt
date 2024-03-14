
export class InvalidPackageInstanceError extends TypeError {
	constructor(property, class_name, package_name) {
		super(`Value ${property} must be an instance of ${class_name} from package "${package_name}". That error is probably caused by two separate installations of "${package_name}". Please, make sure that "${package_name}" in your project is matches "peerDependencies" of "ecwt" package.`);
	}
}

export class EcwtParseError extends Error {
	constructor() {
		super('Cannot parse data to Ecwt token.');
	}
}

export class EcwtInvalidError extends Error {
	constructor(ecwt) {
		super('Ecwt token is invalid.');

		this.ecwt = ecwt;
	}
}

export class EcwtExpiredError extends EcwtInvalidError {
	constructor(ecwt) {
		super();

		this.ecwt = ecwt;
		this.message = 'Ecwt is expired.';
	}
}

export class EcwtRevokedError extends EcwtInvalidError {
	constructor(ecwt) {
		super();

		this.ecwt = ecwt;
		this.message = 'Ecwt is revoked.';
	}
}
