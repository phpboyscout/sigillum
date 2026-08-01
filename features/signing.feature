Feature: Signing release artefacts
  As a release engineer
  I want sigillum to sign artefacts in the form the Rust consumers verify
  So that cargo-binstall and rtb-update can trust what I publish

  # These scenarios drive the BUILT BINARY, not the library. That is the
  # point: sigillum is a thin shell over go/signing-cli, so the risk it
  # carries is in the wiring — which stream a value lands on, whether a
  # flag reaches the library, whether a file appears where documented.
  # A library-level test cannot see any of that.

  Background:
    Given a freshly built sigillum binary
    And an empty working directory

  Scenario: Generate an Ed25519 signing key with a PEM private half
    # The PEM is what makes artefact signing possible without an HSM.
    When I generate an ed25519 key with a pem private half
    Then the command succeeds
    And the file "demo.asc" starts with "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    And the file "demo.pem" starts with "-----BEGIN PRIVATE KEY-----"

  Scenario: Sign a release artefact as minisign
    Given an ed25519 key with a pem private half
    And a release artefact "tool_1.2.3_linux_amd64.tar.gz"
    When I sign that artefact as minisign for project "demo-tool"
    Then the command succeeds
    # rtb-update selects its parser by extension, so the suffix matters.
    And the file "tool_1.2.3_linux_amd64.tar.gz.minisig" exists
    # "RU" is base64 of the prehashed "ED" tag cargo-binstall requires.
    And the signature body starts with "RU"
    And the trusted comment contains "project:demo-tool"

  Scenario: A minisign signature verifies against the published key
    Given an ed25519 key with a pem private half
    And a release artefact "tool_1.2.3_linux_amd64.tar.gz"
    And I have signed that artefact as minisign for project "demo-tool"
    When I verify the signature against the key
    Then the signature is valid

  Scenario: Tampering with the artefact breaks verification
    Given an ed25519 key with a pem private half
    And a release artefact "tool_1.2.3_linux_amd64.tar.gz"
    And I have signed that artefact as minisign for project "demo-tool"
    When I tamper with the artefact
    And I verify the signature against the key
    Then the signature is not valid

  Scenario: Tampering with the signed project field breaks verification
    # The project lives in the trusted comment, which the global
    # signature covers. If it were not covered, recording it would be
    # decoration rather than evidence.
    Given an ed25519 key with a pem private half
    And a release artefact "tool_1.2.3_linux_amd64.tar.gz"
    And I have signed that artefact as minisign for project "demo-tool"
    When I tamper with the project field in the signature
    And I verify the signature against the key
    Then the signature is not valid

  Scenario: The pinnable public key is written to stdout
    # Regression guard. This value is captured and pinned permanently
    # into an immutable crates.io version, and it was once written to
    # stderr — so piping it produced an empty file while a terminal
    # looked entirely correct.
    Given an ed25519 key with a pem private half
    When I ask for the minisign public key
    Then the command succeeds
    And stdout is the minisign public key
    And stderr contains no key material

  Scenario: Publish the public key to a keys site
    Given an ed25519 key with a pem private half
    When I publish the public key for project "demo-tool"
    Then the command succeeds
    And the file "site/minisign/demo-tool/v1.pub" exists
    And the manifest records project "demo-tool" at generation 1
    And the manifest pubkey matches the published key file

  Scenario: Publishing the same key twice changes nothing
    # Publication is add-only, so a re-run doubles as the byte-identity
    # check the rotation runbook requires before any deploy.
    Given an ed25519 key with a pem private half
    And I have published the public key for project "demo-tool"
    When I publish the public key for project "demo-tool"
    Then the command succeeds
    And the manifest is unchanged

  Scenario: Signing reproducibly with a pinned timestamp
    Given an ed25519 key with a pem private half
    And a release artefact "tool_1.2.3_linux_amd64.tar.gz"
    When I sign that artefact as minisign at a pinned time
    And I sign that artefact as minisign at a pinned time again
    Then both signatures are byte-identical

  Scenario: The minisign path refuses an OpenPGP public key
    # An OpenPGP identity has no meaning here, so accepting the flag
    # would leave the operator believing it had been used.
    Given an ed25519 key with a pem private half
    And a release artefact "tool_1.2.3_linux_amd64.tar.gz"
    When I sign that artefact as minisign passing an OpenPGP public key
    Then the command fails
    And stderr mentions "--public-key is not accepted"
