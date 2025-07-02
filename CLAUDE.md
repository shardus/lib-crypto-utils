# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build
- `npm run compile` - Compile TypeScript to JavaScript
- `npm run clean` - Clean build artifacts

### Testing
- `npm test` - Run all unit tests
- Test framework: Jest with ts-jest
- Unit tests located in `test/unit/`
- Integration tests in `test/` root (test-sign-obj.js, test-tag-obj.js)

### Code Quality
- `npm run lint` - Run ESLint
- `npm run format-check` - Check code formatting with Prettier
- `npm run format-fix` - Auto-fix formatting issues
- `npm run check` - Run Google TypeScript Style checks

### Release
- `npm run release:patch` - Release patch version
- `npm run release:minor` - Release minor version
- `npm run release:major` - Release major version
- `npm run release:prerelease` - Release prerelease version

## Architecture

### Core Module Structure
The library exports cryptographic utility functions from `src/index.ts`. Key architectural decisions:

1. **Initialization Pattern**: The library requires initialization with a 32-byte hex key via `init()` before any operations can be performed. This key is used for Blake2b hashing operations.

2. **Signature Format**: Object signatures follow a specific structure:
   ```typescript
   {
     owner: string,  // public key of signer
     sig: string     // signature
   }
   ```

3. **Type System**: Uses `@shardeum-foundation/lib-types` for shared type definitions across the Shardus ecosystem.

4. **Security Considerations**:
   - The `verify()` function is intentionally not exported due to safety concerns
   - Encrypt/decrypt functions are commented out pending security review (GOLD-264)
   - All cryptographic operations use sodium-native (libsodium bindings)

### Key Dependencies
- **sodium-native**: Core cryptographic operations (Blake2b, Ed25519, Curve25519)
- **fast-stable-stringify**: Deterministic JSON stringification for consistent hashing
- **buffer-xor**: XOR operations for cryptographic functions

### Function Categories
1. **Hashing**: `hash()`, `hashObj()`
2. **Key Management**: `generateKeypair()`, `convertSkToCurve()`, `convertPkToCurve()`
3. **Signing**: `sign()`, `signObj()`
4. **Verification**: `verify()` (internal only), `verifyObj()`
5. **Authentication**: `tag()`, `tagObj()`, `authenticate()`, `authenticateObj()`
6. **Utilities**: `randomBytes()`, `stringify()`, `setStringifier()`

### Development Notes
- Node.js version must be exactly 18.19.1
- All releases are published to npm under `@shardeum-foundation/lib-crypto-utils`
- CI/CD uses Shardeum's reusable workflow with configurable checks via repository variables
- The library is security-critical - all changes should be carefully reviewed