Feature: Issuing a rotation manifest
  As a release engineer
  I want sigillum to issue a signed rotation manifest
  So that installed binaries can be told which release keys to trust

  # The fire drill is the first manifest a project publishes: empty, so it
  # changes nothing, and proves the authority key and the updater work
  # before a key is ever compromised (sigillum spec 0008).

  Background:
    Given a freshly built sigillum binary
    And an empty working directory
    And an ed25519 key with a pem private half

  Scenario: The fire drill writes a manifest an updater applies without change
    When I issue an empty rotation manifest with that key
    Then the command succeeds
    And the file "rotate-keys.json" exists
    And the file "rotate-keys.json.minisig" exists
    And the rotation manifest verifies against the key's minisign public key
    And applying it leaves the trust set unchanged at epoch 1

  Scenario: A scheduled manifest cannot revoke a key afresh
    When I issue a scheduled rotation manifest that revokes that key
    Then the command fails
    And stderr mentions "pass --reason compromise"
    And the file "rotate-keys.json" does not exist

  Scenario: A scheduled manifest after a compromise carries its revoke
    # go-tool-base spec 0101 D13, amended 2026-11-27: a release ships only its
    # latest manifest, so an install that skipped the compromise learns of the
    # revoke from the scheduled manifest that repeats it.
    Given a second release key "next.asc"
    When I issue a compromise rotation manifest that adds "next.asc" and revokes that key
    And I issue a scheduled rotation manifest after it into "epoch2"
    Then the command succeeds
    And the manifest in "epoch2" is scheduled at epoch 2 and still revokes that key
    And an install that applies only the manifest in "epoch2" stops trusting that key
