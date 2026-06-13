# Nitlix Seal

Minimal crypto orchestration for apps: deterministic identity keys, content-key encryption, user-key wrapping, and share-ready envelopes.

This is a private internal library that is open-source for transparency and interoperability.

## What it is

`nitlix-seal` helps you:

- derive stable user identity material from a seed phrase
- encrypt content with per-content keys (`CK`)
- wrap content keys with a user key (`UK`) for storage/transit
- prepare key envelopes for recipient sharing with `PUIK` / `PRIK`

It is intentionally small and V8-friendly (browser, Workers, Bun, Node runtimes with WebCrypto support).

## Key terms

- `CK` — Content Key used to encrypt content
- `UK` — User Key used to wrap/unwrap `CK`
- `PUIK` — Public identity key used to receive shared keys
- `PRIK` — Private identity key used to open shared keys
- `GK` — Optional server-side global key for fast-mode server participation

## Quick example

```ts
import { SealClient } from "nitlix-seal";

const client = new SealClient({ UK, PRIK });

const { ciphertext, "CK-UK": CK_UK } = await client.encryptContent({
    content: "hello world",
    CK: "", // empty = generate CK automatically
});

const { content } = await client.decryptContent({
    "CK-UK": CK_UK,
    ciphertext,
});
```

## Exports

- `SealClient`, `SealServer`
- `generateSeedphrase`, `deriveUK`, `deriveIKP`, `generateCK`, `generateKeyPair`
- `wrapCKInPUIK`, `unwrapCKPUIKInPRIK`

## Install

```sh
bun add nitlix-seal
```

## License

MIT
