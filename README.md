
# ECWT
Encrypted CBOR-encoded Web Token

## What is it?

ECWT is module for creating and verifying encrypted CBOR-encoded Web Tokens. It is designed to be used in situations where JWT is used, but there are major differences:

| | JWT | ECWT |
| --- | --- | --- |
| Encoding | 🧐 JSON with base64 | ✅ CBOR <br> 2x smaller output |
| Binary data | 🧐 Double base64 encoding | ✅ Supported out of the box |
| Security | 📝 Signed <br> Payload is readable by everyone | 🔒 Encrypted <br> Payload is readable only by the private key possessor |
| Metadata | ➕ Type and algorithm, increases size | ✅ No unnecessary metadata |
| Revocation | 🧑‍💻 Requires additional implementation | ✅ Included with Redis |

## Installation

ECWT depends on other modules, so you need to install them too.

```
npm install ecwt @kirick/snowflake
pnpm install ecwt @kirick/snowflake
bun install ecwt @kirick/snowflake
```

### Some dependencies

`EcwtFactory` depends on other modules, so you might be need to install them too.

#### `@kirick/snowflake` to create unique IDs (required)

For documentation, see [snowflake-js repository](https://github.com/kirick13/snowflake-js).

```javascript
import { SnowflakeFactory } from '@kirick/snowflake';

const snowflakeFactory = new SnowflakeFactory({
	server_id: 0,
	worker_id: 0,
});
```

#### `redis` to store revoked tokens (optional)

```javascript
import { createClient } from 'redis';

const redisClient = createClient({
	socket: {
		host: 'localhost',
		port: 6379,
	},
});

await redisClient.connect();
```

#### `lru` to avoid decrypt the same token multiple times (optional)

```javascript
import { LRUCache } from 'lru-cache';

const lruCache = new LRUCache({
    max: 1000, // maximum of 1000 items
    ttl: 60 * 60 * 1000, // 1 hour
});
```

#### Validation library of your choice (optional)

By specifying the schema, you also validate the payloads. Schema is a function that takes a value and returns it back or throws.

In our example, we use [valibot](https://valibot.dev) library.

```javascript
import * as v from 'valibot';

const schema = (value) => v.parse(
	v.object({
		user_id: v.number([
			v.maxValue(10),
		]),
		nick: v.string([
			v.maxLength(10),
		]),
	}),
	value,
);
```

That schema will prevent creating tokens for users with ID greater than 10 and nicknames longer than 10 characters.

## API

### `EcwtFactory`

```typescript
constructor({
    redisClient: RedisClientType?,
    lruCache: LRU?,
    snowflakeFactory: SnowflakeFactory,
    options: {
        namespace: string?,
        key: Buffer,
        schema: (value: any) => any,
        senmlKeyMap: {
			[key: string]: number,
		}?,
    },
})
```

Create your `EcwtFactory` instance to create, validate and revoke tokens.

```javascript
import { EcwtFactory } from 'ecwt';

const ecwtFactory = new EcwtFactory({
	redisClient,
	lruCache,
	snowflakeFactory,
	options: {
        // "options.namespace" is required to identify the storage of revoked tokens in Redis
		namespace: 'test',
		key: Buffer.from(
			'54RoavO+7orGGCKqLXcMwNGFGbcnSEq22f9bJX3lT9lgEPSaRAMBaEnHgMQPTPXcifFvGZmDGzOFqUMfqXsAhQ==',
			'base64',
		),
		schema,
		senml_key_map: {
			user_id: 1,
			nick: 2,
		},
	},
});
```

To reduce token size, which is especially important to reduce amount of data sent over the network, you can use `options.senml_key_map` to map keys to numbers. This way, CBOR encoder will use numbers instead of strings in object keys. You **should never change** number assigned to a key or **reassign number** to another key to avoid breaking the schema. For more information, see [RFC 8428](https://datatracker.ietf.org/doc/html/rfc8428#section-6).

#### Class method `create`

```typescript
create(
    payload: {
        [key: string]: any,
    },
    options: {
        ttl: number | null,
    }
): Promise<Ecwt>
```

Creates a token.

`options.ttl` specifies the time to live of the token in seconds. If set to null, token will never expire.

> **Be careful with `ttl　=　null`!**
>
> Revoked tokens are stored in Redis until they expire. Never-expiring tokens will be stored in Redis **forever**, which will lead to uncontrolled Redis database growth.

Returns `Ecwt` instance.

```javascript
// Example
const ecwt = await ecwtFactory.create(
    {
        user_id: 1,
        nick: 'kirick',
    },
    {
        ttl: 30 * 60,
    }
);
```

#### Class method `verify`

```typescript
verify(
    token: string,
): Promise<Ecwt>
```

Parses string representation of the token and verifies it:

- to be decrypted properly,
- for expiration,
- for revocation (if Redis client is provided),
- for schema.

Returns `Ecwt` instance.

If the token is invalid, throws `EcwtInvalidError` which contains `Ecwt` instance in the `ecwt` property.

```javascript
const ecwt = await ecwtFactory.verify(token);
```

#### Class method `safeVerify`

```typescript
safeVerify(
    token: string,
): Promise<{
	success: boolean,
	ecwt: Ecwt | null,
}>
```

The same method as `verify`, but does not throw an error if the token is invalid, expired or revoked.

Property `success` is `true` if the token is valid.

Property `ecwt` is `null` if the token cannot be parsed, otherwise it contains `Ecwt` instance.

```javascript
const {
	success,
	ecwt,
} = await ecwtFactory.safeVerify(token);
```

### `Ecwt`

Represents the token. Its counstructor cannot be called by the user.

```javascript
import { Ecwt } from 'ecwt';
```

#### Class property `readonly token: string`

The string representation of the token.

#### Class property `readonly id: string`

The unique ID of the token.

#### Class property `readonly snowflake: Snowflake`

The `Snowflake` instance of the token. For documentation, see [snowflake-js repository](https://github.com/kirick13/snowflake-js).

#### Class property `readonly ts_expired: number | null`

The timestamp of the token expiration in seconds. Equals to `null` if the token does not expire.

#### Class property `readonly data: { [key: string]: any }`

The payload of the token.

#### Class method `getTTL`

```typescript
getTTL(): number | null
```

Returns current the time to live of the token in seconds. If the token does not expire, returns `null`.

#### Class method `revoke`

```typescript
revoke(): Promise<void>
```

Revokes the token. Attempts to verify the revoked token will throw `EcwtRevokedError`.
