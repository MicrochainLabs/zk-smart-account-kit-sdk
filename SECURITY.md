# Security Policy

## Supported Versions

zk-smart-account-kit-sdk is in pre-1.0 development. Security fixes are applied to the latest released version on npm and to `main`.

| Version | Supported |
|---------|-----------|
| Latest release / `main` | ✅ |
| Older releases | ❌ Upgrade to the latest |

---

## Scope

In scope:

- **Tree and commitment construction** (`zk-label`, `zk-signer`, `zk-scope`): leaf/root computation that diverges from the circuits, allowing forged or invalid commitments
- **Circuit input builders**: inputs that could cause under-constrained or incorrectly bound proofs
- **ABI encoders**: incorrect encoding of init data, public inputs or proof calldata
- **Proof generation helpers**: leaking private witness data (signers, labels, scope rules) outside the caller's process
- **Supply chain**: malicious or tampered published packages, compromised release workflow

Out of scope:

- Vulnerabilities in the Noir circuits or Solidity contracts — report them in [zk-smart-account-kit](https://github.com/MicrochainLabs/zk-smart-account-kit) or [microchain-zk-signers](https://github.com/MicrochainLabs/microchain-zk-signers) following their security policies
- Upstream dependencies (viem, `@zk-kit/lean-imt`, `@iden3/js-crypto`, `@noir-lang/noir_js`, `@aztec/bb.js`) — report those upstream
- Theoretical attacks without a proof of concept

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing:

**security@microchainlabs.xyz**

Include:

1. **Description** of the vulnerability and its impact.
2. **Module / function** affected and the SDK version.
3. **Steps to reproduce** (minimal proof of concept).
4. **Suggested fix** (optional).

### What to expect

- **Acknowledgement** within 48 hours.
- **Triage and severity assessment** within 5 business days.
- Coordinated disclosure, typically within 90 days of the report, or sooner if a fix is available.
- Public credit in the security advisory unless you prefer to remain anonymous.

---

## Bug Bounty

There is currently no formal bug bounty program.
