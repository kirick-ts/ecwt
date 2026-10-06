import basex from 'base-x';
import type { ReadonlyDeep } from './utils/types.js';

export const base62: basex.BaseConverter = basex(
	'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
);

/**
 * Freezes own data properties and Map/Set entries recursively, without invoking getters.
 * Values that reject freezing are retained; built-in and class internal state can remain mutable.
 * @param object - Object to freeze in place.
 * @returns The same object with recursively readonly properties.
 */
export function deepFreeze<T extends object>(object: T): ReadonlyDeep<T> {
	const visited = new WeakSet<object>();
	/** @param value - Value to visit and freeze if supported. */
	function freeze(value: unknown): void {
		if (
			value === null
			|| (typeof value !== 'object' && typeof value !== 'function')
			|| visited.has(value)
		) {
			return;
		}

		visited.add(value);

		if (value instanceof Map) {
			for (const [key, item] of value) {
				freeze(key);
				freeze(item);
			}
		} else if (value instanceof Set) {
			for (const item of value) {
				freeze(item);
			}
		}

		for (const name of Reflect.ownKeys(value)) {
			const descriptor = Object.getOwnPropertyDescriptor(value, name);
			if (descriptor && 'value' in descriptor) {
				freeze(descriptor.value);
			}
		}

		try {
			Object.freeze(value);
		} catch {
			// Non-empty typed arrays (including Buffers) cannot be frozen.
		}
	}

	freeze(object);
	return object as ReadonlyDeep<T>;
}
