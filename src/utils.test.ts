/* eslint-disable jsdoc/require-jsdoc */

import { describe, expect, test, vi } from 'vitest';
import { deepFreeze } from './utils.js';

function isAllowed() {
	return true;
}

describe('deepFreeze', () => {
	test('nested properties, arrays and symbols', () => {
		const symbol = Symbol('data');
		const hidden = { value: true };
		const data = {
			permissions: { admin: false },
			items: [{ value: true }],
			[symbol]: { value: true },
		};
		Object.defineProperty(data, 'hidden', { value: hidden });
		Object.freeze(data);

		expect(deepFreeze(data)).toBe(data);
		expect(Object.isFrozen(data.permissions)).toBe(true);
		expect(Object.isFrozen(data.items)).toBe(true);
		expect(Object.isFrozen(data.items[0])).toBe(true);
		expect(Object.isFrozen(data[symbol])).toBe(true);
		expect(Object.isFrozen(hidden)).toBe(true);
		expect(() => {
			data.permissions.admin = true;
		}).toThrow(TypeError);
	});

	test('cycles and functions', () => {
		const data: Record<string, unknown> = { isAllowed };
		data.self = data;

		expect(deepFreeze(data)).toBe(data);
		expect(Object.isFrozen(data)).toBe(true);
		expect(Object.isFrozen(isAllowed)).toBe(true);
		expect(Object.isFrozen(isAllowed.prototype)).toBe(true);
		expect(isAllowed()).toBe(true);
	});

	test('unsupported values do not prevent freezing other properties', () => {
		const data = {
			bytes: Uint8Array.of(1),
			typed: new Uint16Array([1]),
			empty: new Uint8Array(0),
			view: new DataView(new ArrayBuffer(1)),
			permissions: { admin: false },
		};

		expect(deepFreeze(data)).toBe(data);
		expect(Object.isFrozen(data)).toBe(true);
		expect(Object.isFrozen(data.permissions)).toBe(true);
		expect(Object.isFrozen(data.bytes)).toBe(false);
		expect(Object.isFrozen(data.typed)).toBe(false);
		expect(Object.isFrozen(data.empty)).toBe(true);
		expect(Object.isFrozen(data.view)).toBe(true);
		data.bytes[0] = 2;
		data.typed[0] = 2;
		data.view.setUint8(0, 2);
		expect(data.bytes[0]).toBe(2);
		expect(data.typed[0]).toBe(2);
		expect(data.view.getUint8(0)).toBe(2);
	});

	test('Map and Set entries', () => {
		const key = { id: 1 };
		const item = { admin: false };
		const data = {
			map: new Map([[key, item]]),
			set: new Set([item]),
			date: new Date(0),
		};

		deepFreeze(data);

		expect(Object.isFrozen(data.map)).toBe(true);
		expect(Object.isFrozen(data.set)).toBe(true);
		expect(Object.isFrozen(data.date)).toBe(true);
		expect(Object.isFrozen(key)).toBe(true);
		expect(Object.isFrozen(item)).toBe(true);
		expect(data.map.get(key)).toBe(item);
		expect(data.set.has(item)).toBe(true);
		data.date.setTime(1);
		expect(data.date.getTime()).toBe(1);
	});

	test('getters are not invoked', () => {
		const getter = vi.fn(() => {
			throw new Error('Getter must not run while freezing');
		});
		const data = Object.defineProperty({}, 'value', { get: getter });

		expect(deepFreeze(data)).toBe(data);
		expect(Object.isFrozen(data)).toBe(true);
		expect(getter).not.toHaveBeenCalled();
	});
});
