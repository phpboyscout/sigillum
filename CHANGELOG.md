# Changelog

## [v0.4.1](https://gitlab.com/phpboyscout/sigillum/-/releases/v0.4.1)

[Compare to previous version](https://gitlab.com/phpboyscout/sigillum/-/compare/v0.4.0...v0.4.1)

### Bug Fixes

- **deps**: update go modules ([bd6905f](https://gitlab.com/phpboyscout/sigillum/-/commit/bd6905f3280b4ccb1052647811d5ffbd9dc3de78))
- **deps**: update go modules ([8c3c3d1](https://gitlab.com/phpboyscout/sigillum/-/commit/8c3c3d17542def176a394eff38efcffeb26a4555))
- **deps**: update module gitlab.com/phpboyscout/go-tool-base to v0.39.1 ([2ab4ae9](https://gitlab.com/phpboyscout/sigillum/-/commit/2ab4ae9ae08e51a82c0a6b9555bcda29c00a4b63))
- **deps**: update module gitlab.com/phpboyscout/go/signing-cli to v0.6.1 ([0d9a4bd](https://gitlab.com/phpboyscout/sigillum/-/commit/0d9a4bd1a331d80cab945125f25ff7a7a4a995eb))

## [v0.4.0](https://gitlab.com/phpboyscout/sigillum/-/releases/v0.4.0)

[Compare to previous version](https://gitlab.com/phpboyscout/sigillum/-/compare/v0.3.0...v0.4.0)

### Features

- **deps**: bump the signing stack to enable named backend instances ([1d9c415](https://gitlab.com/phpboyscout/sigillum/-/commit/1d9c415f0977a41c5b7dc80bb842485890cb5712))

### Bug Fixes

- **deps**: update go modules ([1e642b9](https://gitlab.com/phpboyscout/sigillum/-/commit/1e642b90a6f7be983bdce8c674a4d1b916fdc80b))
- **deps**: update module gitlab.com/phpboyscout/go/errorhandling to v0.4.0 ([630d732](https://gitlab.com/phpboyscout/sigillum/-/commit/630d732ee9edd3effd5f62ee7708103787b5e06f))

## [v0.3.0](https://gitlab.com/phpboyscout/sigillum/-/releases/v0.3.0)

[Compare to previous version](https://gitlab.com/phpboyscout/sigillum/-/compare/v0.2.2...v0.3.0)

### Features

- **certificate**: offer byte-reproducible output with --signed-at and --reproducible ([a7b2adf](https://gitlab.com/phpboyscout/sigillum/-/commit/a7b2adf3312fa0aac1eb6085240df8d9d27b9887))
- **openpgp**: propagate certificate findings, and report them before erroring ([d9bdd6c](https://gitlab.com/phpboyscout/sigillum/-/commit/d9bdd6c474118c37968cc307bedf97babb011b7f))
- **sigillum**: ship the local encryption backend, and decrypt a report end to end ([57dbac7](https://gitlab.com/phpboyscout/sigillum/-/commit/57dbac77e643e29f5040d78f50458aeb9a0b8d4f))
- **decrypt**: warn the operator about what the certificate parser could not decide ([31afa42](https://gitlab.com/phpboyscout/sigillum/-/commit/31afa42d61a64a0b5726c6aa32f57dd0e837a956))
- **opfile**: make following a symbolic link the caller's decision ([d24487c](https://gitlab.com/phpboyscout/sigillum/-/commit/d24487c2489092242aff2c5b73ce2c4fc93b7c5a))
- **opfile**: replace an output file only once the work has succeeded ([c22c00f](https://gitlab.com/phpboyscout/sigillum/-/commit/c22c00fae7d712d1cc23582353e361d072ceca67))
- read encrypted vulnerability reports, and publish the certificate ([ed5f74b](https://gitlab.com/phpboyscout/sigillum/-/commit/ed5f74baf629a4d388cbed00b415998de3a916a5))
- **ci**: announce releases to Discord ([842ee4e](https://gitlab.com/phpboyscout/sigillum/-/commit/842ee4ec8d16c17047dd1efab23c7bc803b53bc8))

### Bug Fixes

- **decrypt**: decrypt through a withdrawn certificate with a loud warning ([5504a03](https://gitlab.com/phpboyscout/sigillum/-/commit/5504a03ff499a82a97174ca3982b96a7a747b286))
- **openpgp**: read a streaming message for another key as not addressed ([6642b89](https://gitlab.com/phpboyscout/sigillum/-/commit/6642b890a78b983d356c05fb267c26fe70187f86))
- **openpgp**: try every unwrapped session key against the body ([5b10ab0](https://gitlab.com/phpboyscout/sigillum/-/commit/5b10ab061d32bc2c5f08bc23cdb5424858ca29e7))
- **opfile**: report a post-rename flush failure as durability-unconfirmed ([78166a4](https://gitlab.com/phpboyscout/sigillum/-/commit/78166a49a2d3cf102fac99c3f1723863e95d878b))
- **openpgp**: do not bound the outer decrypt walk ([3cfaaab](https://gitlab.com/phpboyscout/sigillum/-/commit/3cfaaab366483a35285522ae16470c830bf85b21))
- **opdest**: refuse a followed symlink output that resolves to an input ([82d3309](https://gitlab.com/phpboyscout/sigillum/-/commit/82d3309086d62f468e8fc466689cf8cdc6cb95fd))
- **opfile**: flush the containing directory so a commit is durable ([5f9ebc9](https://gitlab.com/phpboyscout/sigillum/-/commit/5f9ebc92abb8b02a6bce84c68cd0cb891da957c7))
- close the two guard defects the round-8 fixes left in their siblings ([c5b8d61](https://gitlab.com/phpboyscout/sigillum/-/commit/c5b8d61e1d69ab9f1b49099a897e222837a29c0d))
- **openpgp**: stop three guards taking the rest of the walk down with them ([c36c282](https://gitlab.com/phpboyscout/sigillum/-/commit/c36c2826de11212f087b66142933aa764162318f))
- **certificate**: keep the fingerprint explanation when --created is missing ([3a0e942](https://gitlab.com/phpboyscout/sigillum/-/commit/3a0e9425f40cf2b9960058b7b9b77f50c5285960))
- **cmd**: stop certificate overwriting the private key it was given ([70e08d0](https://gitlab.com/phpboyscout/sigillum/-/commit/70e08d0d4d483c764b760b178ea65018db603e0e))
- **decrypt**: refuse writing over an input, and wire the key service once ([deb5240](https://gitlab.com/phpboyscout/sigillum/-/commit/deb52407f76ac59a048af49e1db70dcabb876229))
- **cmd**: surface the file mode the filesystem would not set ([7811dd9](https://gitlab.com/phpboyscout/sigillum/-/commit/7811dd926a0ad4a84ab3fb0ce2e7be3774c13ba1))
- **openpgp**: stream the candidate walk instead of collecting it ([821f50f](https://gitlab.com/phpboyscout/sigillum/-/commit/821f50f287a82396e0f1104ed857b271ec029731))
- **decrypt**: stop saying the same thing twice, in errors and in comments ([03d3d1e](https://gitlab.com/phpboyscout/sigillum/-/commit/03d3d1eb16a1546439d7c6f8fb80fbe562a7c04e))
- **openpgp**: make the dedup key injective and bound what the walk retains ([6144d6e](https://gitlab.com/phpboyscout/sigillum/-/commit/6144d6eabb22e307fb27aba08cae8880f14b6160))
- **opfile**: set the staged mode through the handle, and survive a filesystem ([6f8282b](https://gitlab.com/phpboyscout/sigillum/-/commit/6f8282bc558ec6ebf300e940f0a8cbaadd6d52a1))
- **openpgp**: bill one derivation per point even when the key service refuses ([7cd0a11](https://gitlab.com/phpboyscout/sigillum/-/commit/7cd0a1132d3dcabb0dc738c99f07ce8ebc6529e8))
- **openpgp**: skip candidates the ceiling refuses, do not abandon the run ([451c606](https://gitlab.com/phpboyscout/sigillum/-/commit/451c606e3d5e05c88c30c1b079e30577c02c422b))
- **test**: frame packets with a length bound that compiles on 32-bit ([0a56623](https://gitlab.com/phpboyscout/sigillum/-/commit/0a56623679f0e7c7d55dc128409a5b47a0258bea))
- **openpgp**: decide packets-or-armour by walking, not by one header ([1c237e0](https://gitlab.com/phpboyscout/sigillum/-/commit/1c237e0e5af1d52ef3d23d1adabd034a5181a739))
- **decrypt**: refuse more than one message instead of silently ignoring the rest ([9a3d68e](https://gitlab.com/phpboyscout/sigillum/-/commit/9a3d68ef150f5f87dd1e9ece1036c720411a668f))
- **openpgp**: bound what is retained to name a message's recipients, not just ([e29741a](https://gitlab.com/phpboyscout/sigillum/-/commit/e29741a21d07b1697f16046bec96114c83fe9801))
- **opfile**: resolve link chains within budget, and clean up exactly once ([b5dd163](https://gitlab.com/phpboyscout/sigillum/-/commit/b5dd163035c3757e9b9bc5db16eb96af56a0b77b))
- **cmd**: report where the output actually landed, from one shared destination ([56a8289](https://gitlab.com/phpboyscout/sigillum/-/commit/56a8289f9be4ca9a2396381b92f4049054f1d447))
- **opfile**: set the staged file's mode instead of letting the umask decide ([db78abf](https://gitlab.com/phpboyscout/sigillum/-/commit/db78abf9646604b50567f7173b8c59c02774c963))
- **openpgp**: bound distinct key-service derivations per message ([f9630f1](https://gitlab.com/phpboyscout/sigillum/-/commit/f9630f13793d9667a2ffd84c383738989a8bb36b))
- **openpgp**: bill one derivation per ephemeral point, not per packet ([ad19667](https://gitlab.com/phpboyscout/sigillum/-/commit/ad196674f3b21cfaa82ad30576a735bb94045434))
- **openpgp**: bound guesses, not packets an attacker can forge ([8ca1905](https://gitlab.com/phpboyscout/sigillum/-/commit/8ca19055a3968921257ad764cc43396621ed4309))
- **openpgp**: end the session-key scan at the encrypted data, and diagnose honestly ([fa8a67c](https://gitlab.com/phpboyscout/sigillum/-/commit/fa8a67ce935166bb1359becec41b0f1e19b61298))
- **openpgp**: stop the cap being the attack, and keep what it learned ([9d6ac16](https://gitlab.com/phpboyscout/sigillum/-/commit/9d6ac16e994054a56bfff08232d55c6951db8ef2))
- **certificate**: name every missing flag, in a fixed order ([a525676](https://gitlab.com/phpboyscout/sigillum/-/commit/a5256764cc8cfffb267296fde4b5cd442cc7dbe6))
- **openpgp**: decide armour by asking what the input is, and bound packet breadth ([676b777](https://gitlab.com/phpboyscout/sigillum/-/commit/676b777daaaa6b8925c5279808a69750111baa4c))
- **openpgp**: try every candidate, and report why when none opens ([25a7c0d](https://gitlab.com/phpboyscout/sigillum/-/commit/25a7c0d6bdb7bb254ce86712ab017cbed3d02b19))
- **decrypt**: clean up the temporary file, and refuse the stdin pair ([e6ac07f](https://gitlab.com/phpboyscout/sigillum/-/commit/e6ac07fdbcabb4fb314c4076e5080b6f340da605))
- **openpgp**: bound compression depth and anchor the armour probe ([db7ffbf](https://gitlab.com/phpboyscout/sigillum/-/commit/db7ffbff25582257563e280e9340391a2160017f))
- **openpgp**: try every candidate session-key packet, within a cap ([b240596](https://gitlab.com/phpboyscout/sigillum/-/commit/b2405965007c87c240f8caf80e29ada8446fba6a))
- **openpgp**: bound message reading and walk every session-key packet ([3d1d55d](https://gitlab.com/phpboyscout/sigillum/-/commit/3d1d55df3fd851e80e8f08f571037233618730cb))
- **deps**: update module gitlab.com/phpboyscout/go-tool-base to v0.38.0 ([cfcf2be](https://gitlab.com/phpboyscout/sigillum/-/commit/cfcf2bee142241082aaaf7c1d47c67f793193235))
- **deps**: update module gitlab.com/phpboyscout/go-tool-base to v0.37.1 ([64ff98f](https://gitlab.com/phpboyscout/sigillum/-/commit/64ff98fda7cc5e70e4a1cea18c1247f517480309))
- **deps**: take golang.org/x/mod to v0.40.0 for GO-2026-6179/6180 ([61b4853](https://gitlab.com/phpboyscout/sigillum/-/commit/61b48537073830f77bda62472ca46537ffa5ce18))
- **deps**: require go 1.26.6 for the stdlib advisories ([748b68f](https://gitlab.com/phpboyscout/sigillum/-/commit/748b68f95711113f8fcfb2e7094a2bb708266824))
- **ci**: bump the cicd components to v0.36.0 for Go 1.26.6 ([901f648](https://gitlab.com/phpboyscout/sigillum/-/commit/901f6484a4a6188e20734e8e6aba1e20093467f2))
- **deps**: update module gitlab.com/phpboyscout/go-tool-base to v0.37.0 ([4de8c45](https://gitlab.com/phpboyscout/sigillum/-/commit/4de8c4526e6a65628852594b9f960bbc78cd7163))
- add the MIT licence file ([31d0788](https://gitlab.com/phpboyscout/sigillum/-/commit/31d07888c7113307e9bd6d8370ce5813017d1361))
- **deps**: update go modules ([34b08fa](https://gitlab.com/phpboyscout/sigillum/-/commit/34b08fafd8c07e0ff8c93bb169137cc9d9ca2b01))
- **build**: point the golangci-lint tool directive at v2 ([0a9e916](https://gitlab.com/phpboyscout/sigillum/-/commit/0a9e9160713dad6475aa14fa333729d9c8eb6270))

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
