/* Types from type-fest (https://github.com/sindresorhus/type-fest) */

// oxlint-disable typescript/no-explicit-any typescript/no-empty-object-type typescript/array-type typescript/no-invalid-void-type

type Primitive = null | undefined | string | number | boolean | symbol | bigint;
type BuiltIns = Primitive | void | Date | RegExp;
type HasMultipleCallSignatures<T extends (...arguments_: any[]) => unknown> =
	T extends {
		(...arguments_: infer A): unknown;
		(...arguments_: infer B): unknown;
	}
		? B extends A
			? A extends B
				? false
				: true
			: true
		: false;

export type ReadonlyDeep<T> = T extends BuiltIns
	? T
	: T extends new (
				...arguments_: any[]
			) => unknown
		? T // Skip class constructors
		: T extends (...arguments_: any[]) => unknown
			? {} extends _ReadonlyObjectDeep<T>
				? T
				: HasMultipleCallSignatures<T> extends true
					? T
					: ((...arguments_: Parameters<T>) => ReturnType<T>) &
							_ReadonlyObjectDeep<T>
			: T extends Readonly<ReadonlyMap<infer KeyType, infer ValueType>>
				? ReadonlyMapDeep<KeyType, ValueType>
				: T extends Readonly<ReadonlySet<infer ItemType>>
					? ReadonlySetDeep<ItemType>
					: // Identify tuples to avoid converting them to arrays inadvertently; special case `readonly [...never[]]`, as it emerges undesirably from recursive invocations of ReadonlyDeep below.
						T extends readonly [] | readonly [...never[]]
						? readonly []
						: T extends readonly [infer U, ...infer V]
							? readonly [ReadonlyDeep<U>, ...ReadonlyDeep<V>]
							: T extends readonly [...infer U, infer V]
								? readonly [...ReadonlyDeep<U>, ReadonlyDeep<V>]
								: T extends ReadonlyArray<infer ItemType>
									? ReadonlyArray<ReadonlyDeep<ItemType>>
									: T extends object
										? _ReadonlyObjectDeep<T>
										: unknown;

type ReadonlyMapDeep<KeyType, ValueType> = {} & Readonly<
	ReadonlyMap<ReadonlyDeep<KeyType>, ReadonlyDeep<ValueType>>
>;
type ReadonlySetDeep<ItemType> = {} & Readonly<
	ReadonlySet<ReadonlyDeep<ItemType>>
>;
type _ReadonlyObjectDeep<ObjectType extends object> = {
	readonly [KeyType in keyof ObjectType]: ReadonlyDeep<ObjectType[KeyType]>;
};
