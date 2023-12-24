
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

To reduce the size of the token, ECWT does not include object keys in the payload. By specifying the schema, you also can validate the payloads.

In our example, we use [valibot](https://valibot.dev) library.

```javascript
import {
	number,
	string,
	maxValue,
	maxLength,
	safeParse } from 'valibot';

const schema = {
    user_id: (value) => safeParse(
        number([
            maxValue(10),
        ]),
        value,
    ).success,
    nick: (value) => safeParse(
        string([
            maxLength(10),
        ]),
        value,
    ).success,
};
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
        schema: {
            [key: string]: (value: any) => boolean,
        } = {},
    },
})
```

Create your `EcwtFactory` instance to create, and parse tokens.

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
	},
});
```

#### Class method `create`

```typescript
create(
    payload: {
        [key: string]: any,
    },
    options: {
        ttl: number?,
    }
): Promise<Ecwt>
```

Creates a token.

`options.ttl` specifies the time to live of the token in seconds. If not specified, the token will not expire.

Returns `Ecwt` instance.

```javascript
const ecwt_token = await ecwtFactory.create(
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
const ecwt_token = await ecwtFactory.verify(token);
```

### `Ecwt`

Represents the token. It cannot be created by the user.

```javascript
import { Ecwt } from 'ecwt';
```

#### Class property `token: string`

The string representation of the token.

#### Class property `id: string`

The unique ID of the token.

#### Class property `snowflake: Snowflake`

The `Snowflake` instance of the token. For documentation, see [snowflake-js repository](https://github.com/kirick13/snowflake-js).

#### Class property `ts_expired: number`

The timestamp of the token expiration in seconds. If the token does not expire, it is `Number.POSITIVE_INFINITY`.

#### Class property `ttl: number`

Current the time to live of the token in seconds. If the token does not expire, it is `Number.POSITIVE_INFINITY`.

#### Class property `data: { [key: string]: any }`

The payload of the token.

#### Class method `revoke`

```typescript
revoke(): Promise<void>
```

Revokes the token. It will be impossible to verify it after that.
