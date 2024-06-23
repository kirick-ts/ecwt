
// @ts-check

/**
 * Convert timestamp in seconds to milliseconds.
 * @param {*} value Timestamp in milliseconds.
 * @returns {number} Timestamp in seconds.
 */
export function toSeconds(value) {
	return Math.floor(value / 1000);
}

// /**
//  * Returns current timestamp in seconds.
//  * @returns {number} Timestamp in seconds.
//  */
// export function unixtime() {
// 	return toSeconds(Date.now());
// }
