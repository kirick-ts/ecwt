# ECWT

[![npm version](https://img.shields.io/npm/v/ecwt.svg)](https://www.npmjs.com/package/ecwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

ECWT is module for creating and verifying encrypted CBOR Web Tokens. It is designed to be used in situations where JWT is used, but there are major differences:

| | JWT | ECWT |
| --- | --- | --- |
| Encoding | 🧐 JSON with base64 | ✅ CBOR <br> 2x smaller output |
| Binary data | 🧐 Double base64 encoding | ✅ Supported out of the box |
| Security | 📝 Signed <br> Payload is readable by everyone | 🔒 Encrypted <br> Payload is readable only by the private key possessor |
| Metadata | ➕ Type and algorithm, increases size | ✅ No unnecessary metadata |
| Revocation | 🧑‍💻 Requires additional implementation | ✅ Included with Redis |

## Installation

ECWT depends on other modules, so you need to install them too.

```sh
npm install ecwt @kirick/snowflake
# or
pnpm install ecwt @kirick/snowflake
# or
bun install ecwt @kirick/snowflake
```

### Some dependencies

`EcwtFactory` depends on other modules, so you might be need to install them too.

#### `@kirick/snowflake` to create unique IDs (required)

For documentation, see [snowflake repository](https://github.com/kirick-ts/snowflake).

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

#### `lru-cache` to avoid decrypt the same token multiple times (optional)

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

const validator = v.parser(
  v.object({
    user_id: v.pipe(
      v.number(),
      v.maxValue(10),
    ),
    nick: v.pipe(
      v.string(),
      v.maxLength(10),
    ),
  }),
);
```

That validator will prevent creating tokens for users with ID greater than 10 and nicknames longer than 10 characters.

## Usage Examples

### Initializing the EcwtFactory

First, configure the EcwtFactory with your environment dependencies:

```javascript
import { EcwtFactory } from 'ecwt';
import { SnowflakeFactory } from '@kirick/snowflake';
import { LRUCache } from 'lru-cache';
import { createClient } from 'redis';

// Required: Initialize SnowflakeFactory for token ID generation
const snowflakeFactory = new SnowflakeFactory({
  server_id: 0,
  worker_id: 0,
});

// Optional but recommended: Configure LRU cache for performance optimization
const lruCache = new LRUCache({
  max: 1000, // Maximum cache size
  ttl: 60 * 60 * 1000, // Cache expiration (1 hour)
});

// Optional: Set up Redis client for token revocation capabilities
const redisClient = createClient({
  socket: {
    host: 'localhost',
    port: 6379,
  },
});
await redisClient.connect();

// Initialize the factory with your configuration
const ecwtFactory = new EcwtFactory({
  redisClient,
  lruCache,
  snowflakeFactory,
  options: {
    // Unique namespace for Redis keys to prevent collisions
    namespace: 'auth-service',
    // Your 64-byte encryption key (store securely)
    key: Buffer.from('YOUR_BASE64_KEY', 'base64'),
    // Schema validator for payload structure validation
    validator: myValidator,
  },
});
```

### Token Generation

Generate tokens with precise payload and expiration controls:

```javascript
// Create an access token with a 30-minute expiration
const ecwt = await ecwtFactory.create(
  {
    user_id: 123,
    name: "John Doe",
    role: "admin"
  },
  {
    ttl: 30 * 60 // 30 minutes in seconds
  }
);

// Get string representation of the token
const serializedToken = ecwt.token;

// Access token metadata
console.log(`Token ID: ${ecwt.id}`);
console.log(`Expiration timestamp: ${ecwt.ts_expired}`);
console.log(`Remaining validity: ${ecwt.getTTL()} seconds`);
```

> **Warning regarding non-expiring tokens:**
>
> When using `ttl: null`, revoked tokens remain in Redis storage indefinitely. This can lead to uncontrolled database growth over time as these tokens are never automatically purged. Consider implementing a periodic cleanup strategy if non-expiring tokens are required.

### Token Verification

Implement verification with appropriate error handling:

```javascript
import {
  EcwtExpiredError,
  EcwtRevokedError,
  EcwtParseError,
  EcwtInvalidError
} from 'ecwt';

try {
  // Verify and decode the token
  const verifiedToken = await ecwtFactory.verify(serializedToken);

  // Access verified payload data
  const { user_id, name, role } = verifiedToken.data;

  // Proceed with authenticated operation

} catch (error) {
  // Handle specific verification failures
  if (error instanceof EcwtExpiredError) {
    return respondWithError(401, "Authentication expired");
  } else if (error instanceof EcwtRevokedError) {
    return respondWithError(401, "Authentication revoked");
  } else if (error instanceof EcwtParseError) {
    return respondWithError(400, "Malformed authentication token");
  } else if (error instanceof EcwtInvalidError) {
    return respondWithError(401, "Invalid authentication token");
  } else {
    logger.error("Token verification error", error);
    return respondWithError(500, "Authentication service error");
  }
}
```

For exception-free verification, use `safeVerify`:

```javascript
const { success, ecwt } = await ecwtFactory.safeVerify(serializedToken);

if (success) {
  // Proceed with authenticated request
  const userData = ecwt.data;
  return processAuthenticatedRequest(userData);
} else if (ecwt) {
  // Token structure was valid but failed verification
  logger.info(`Auth failure: token ${ecwt.id} is invalid`);
  return respondWithError(401, "Authentication token invalid");
} else {
  // Unparsable token structure
  logger.warn(`Auth failure: malformed token received`);
  return respondWithError(400, "Malformed authentication token");
}
```

### Token Revocation

Implement secure session termination with token revocation:

```javascript
// Terminate user session by revoking the token
await accessToken.revoke();
logger.info(`Session terminated: Token ${accessToken.id} revoked`);

// Subsequent verification attempts will fail with EcwtRevokedError
try {
  await ecwtFactory.verify(accessToken.token);
} catch (error) {
  if (error instanceof EcwtRevokedError) {
    // Expected behavior for revoked tokens
    logger.debug("Token verification correctly rejected revoked token");
  }
}
```

### Advanced: Token Size Optimization

To reduce token size, use SenML key mapping that replaces string object keys with numeric identifiers throughout your entire payload structure. This compression works at any nesting depth. When implementing, catalog all potential keys across your schema and assign consistent numeric values to each, as these mappings cannot be changed once tokens are in circulation.

> **Important:** The SenML key mapping configuration establishes a permanent relationship between field names and their numeric identifiers. Once deployed, these mappings must remain consistent to maintain compatibility with existing tokens. Adding new fields is acceptable, but changing existing mappings can break previously issued tokens.

```javascript
// Standard configuration without key mapping
const standardFactory = new EcwtFactory({
  /* Core dependencies */
  options: {
    namespace: 'auth-service',
    key: encryptionKey,
  },
});

// Optimized configuration with key mapping
const optimizedFactory = new EcwtFactory({
  /* Core dependencies */
  options: {
    namespace: 'auth-service',
    key: encryptionKey,
    senml_key_map: {
      user_id: 1,
      name: 2,
      roles: 3,
      permissions: 4,
      metadata: 5,
      last_login: 6,
    },
  },
});

// Measure token size difference
const payload = {
  user_id: 12345,
  name: "John Smith",
  roles: ["admin", "editor"],
  permissions: ["read", "write", "delete"],
  metadata: { last_login: Date.now() },
};

const standardToken = await standardFactory.create(payload, { ttl: 3600 });
const optimizedToken = await optimizedFactory.create(payload, { ttl: 3600 });

console.log(`Standard token size: ${standardToken.token.length} bytes`);
console.log(`Optimized token size: ${optimizedToken.token.length} bytes`);
console.log(`Size reduction: ${(1 - optimizedToken.token.length / standardToken.token.length).toFixed(2) * 100}%`);

// Outputs:
// > Standard token size: 210 bytes
// > Optimized token size: 146 bytes
// > Size reduction: 30%
```
