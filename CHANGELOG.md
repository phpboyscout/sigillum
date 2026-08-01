# Changelog

## [v0.2.2](https://gitlab.com/phpboyscout/sigillum/-/releases/v0.2.2)

[Compare to previous version](https://gitlab.com/phpboyscout/sigillum/-/compare/v0.2.1...v0.2.2)

### Bug Fixes

- **deps**: pin signing-aws-kms v0.3.0 for the Ed25519 KMS branch ([06dbd37](https://gitlab.com/phpboyscout/sigillum/-/commit/06dbd3772518ae4c2310025b9fbf842dbde1ee50))
- **cli**: align the attach manifest with the pinned signing-cli ([6aed19a](https://gitlab.com/phpboyscout/sigillum/-/commit/6aed19afe23ce248ac28fbd55f13a3e063987185))
- **deps**: update go dependencies ([6dfd534](https://gitlab.com/phpboyscout/sigillum/-/commit/6dfd534e8432860dfd0b71fc69a7685706cee8c8))
- **deps**: update go dependencies ([0233979](https://gitlab.com/phpboyscout/sigillum/-/commit/0233979e786a2fa98487f6c1a203e8d42db048ef))

## [v0.2.1](https://gitlab.com/phpboyscout/sigillum/-/releases/v0.2.1)

[Compare to previous version](https://gitlab.com/phpboyscout/sigillum/-/compare/v0.2.0...v0.2.1)

### Bug Fixes

- **release**: make sigillum stateless — disable the init feature ([3680176](https://gitlab.com/phpboyscout/sigillum/-/commit/36801762378fb956f989511aee525d009348c5d7))
- **release**: skip the config gate for the sign/keys commands ([5990a2d](https://gitlab.com/phpboyscout/sigillum/-/commit/5990a2d5129990a57d922f8d24a6850b0a2e6acf))

## [v0.2.0](https://gitlab.com/phpboyscout/sigillum/-/releases/v0.2.0)

[Compare to previous version](https://gitlab.com/phpboyscout/sigillum/-/compare/v0.1.0...v0.2.0)

### Features

- **release**: enable signing, macOS notarization, and self-update verification ([119ab1d](https://gitlab.com/phpboyscout/sigillum/-/commit/119ab1d4b15a540f056b5c459c802fe1e74ffdcf))

### Bug Fixes

- **deps**: update module gitlab.com/phpboyscout/go/signing-aws-kms to v0.2.5 ([1f895f8](https://gitlab.com/phpboyscout/sigillum/-/commit/1f895f81c711bd172cdbb65732a521a4e9d726df))

## [v0.1.0](https://gitlab.com/phpboyscout/sigillum/-/releases/v0.1.0)

### Features

- attach the sign/keys command tree from go/signing-cli ([817d654](https://gitlab.com/phpboyscout/sigillum/-/commit/817d6549a83f5b508c834ef65418aa58da5b63b5))
