/**
 * @typedef {import('../token.js').Ecwt} Ecwt
 */
export class InvalidPackageInstanceError extends TypeError {
    /**
     * @param {string} property -
     * @param {string} class_name -
     * @param {string} package_name -
     */
    constructor(property: string, class_name: string, package_name: string);
}
/**
 * Error thrown when string token cannot be parsed to Ecwt.
 */
export class EcwtParseError extends Error {
    constructor();
}
/**
 * Error thrown when parsed Ecwt is invalid.
 */
export class EcwtInvalidError extends Error {
    /**
     * @param {Ecwt} ecwt -
     */
    constructor(ecwt: Ecwt);
    ecwt: import("../token.js").Ecwt;
}
/**
 * Error thrown when parsed Ecwt is expired.
 */
export class EcwtExpiredError extends EcwtInvalidError {
}
/**
 * Error thrown when parsed Ecwt is revoked.
 */
export class EcwtRevokedError extends EcwtInvalidError {
}
export type Ecwt = import("../token.js").Ecwt;
