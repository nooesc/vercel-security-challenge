import { describe, expect, it } from 'vitest';
import { deserialize, serialize } from './serialization';

describe('security PoC: cross-group precompute token replay', () => {
  it('reinterprets a signed value from one group as a privileged value in another', async () => {
    const secret = '0123456789abcdef0123456789abcdef';

    const publicFlags = [
      {
        key: 'theme',
        options: [{ value: 'light' }, { value: 'dark' }],
      },
    ] as const;

    const issuedToken = await serialize(
      { theme: 'dark' },
      publicFlags,
      secret,
    );

    const privilegedFlags = [
      {
        key: 'admin-preview',
        options: [{ value: false }, { value: true }],
      },
    ] as const;

    await expect(
      deserialize(issuedToken, privilegedFlags, secret),
    ).resolves.toEqual({ 'admin-preview': true });
  });
});

