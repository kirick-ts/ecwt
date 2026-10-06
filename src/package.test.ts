import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { expect, test } from 'vitest';
import { data_ecwt as data, key, snowflake_options } from './test-fixtures.js';

for (const format of ['commonjs', 'module'] as const) {
	test(`Node.js package ${format}`, () => {
		// Use Node itself: Bun and Vitest can hide CommonJS interop failures.
		const imports =
			format === 'commonjs'
				? `const { EcwtFactory } = require('ecwt');
				   const { SnowflakeFactory } = require('@kirick/snowflake');`
				: `import { EcwtFactory } from 'ecwt';
				   import { SnowflakeFactory } from '@kirick/snowflake';`;
		const script = `
			${imports}
			async function main() {
				const factory = new EcwtFactory({
					snowflakeFactory: new SnowflakeFactory(${JSON.stringify(snowflake_options)}),
					options: {
						key: Buffer.from(${JSON.stringify(key.toString('base64'))}, 'base64'),
						lru_cache: { max: 10 },
					},
				});
				const created = await factory.create(${JSON.stringify(data)}, { ttl: 60 });
				const verified = await factory.verify(created.token);
				process.stdout.write(JSON.stringify(verified.data));
			}
			main().catch((error) => {
				console.error(error);
				process.exitCode = 1;
			});
		`;
		const output = execFileSync(
			'node',
			['--input-type', format, '--eval', script],
			{
				cwd: fileURLToPath(new URL('..', import.meta.url)),
				encoding: 'utf8',
				timeout: 5000,
			},
		);

		expect(JSON.parse(output)).toStrictEqual(data);
	});
}
