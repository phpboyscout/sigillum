Feature: Signing container images
  As a release engineer
  I want sigillum to sign an image by digest and push the signature to its registry
  So that a consumer can prove the image came from estate CI unaltered

  # These drive the built binary against a registry served in the test
  # process. Whether cosign accepts the result is checked separately, by
  # `just test-cosign`, because the CI image has no cosign.

  Background:
    Given a freshly built sigillum binary
    And an empty working directory

  Scenario: Generate an image-signing key
    When I generate an image-signing key
    Then the command succeeds
    And the file "image.pub" starts with "-----BEGIN PUBLIC KEY-----"
    And the file "image.key" starts with "-----BEGIN PRIVATE KEY-----"
    And the file "image.key" is readable by its owner only

  Scenario: Sign a container image by digest
    Given an image-signing key
    And an image pushed to a local registry
    When I sign that image by digest
    Then the command succeeds
    # Only the two locations reach stdout, so a pipeline can read them.
    And stdout names the image's signature and bundle, and nothing else
    And the registry holds a signature for the image

  Scenario: Signing by tag is refused
    # Signing what a tag points at now races whoever moves the tag next.
    Given an image-signing key
    And an image pushed to a local registry
    When I sign that image by its tag
    Then the command fails
    And stderr mentions "names a tag"
    And the registry holds no signature for the image
