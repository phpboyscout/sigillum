@encryption @cli
Feature: Reading an encrypted vulnerability report
  As someone on the security rota
  I want to read a report a researcher encrypted to our published certificate
  So that a vulnerability reaches us without being readable in transit, at rest
  in the ticket system, or by anyone off the rota.

  Opening a real report needs a key service, so the scenarios that would spend
  a billable call live in the provider's integration suite. What is checked
  here is everything the command decides on its own — and one property that
  matters precisely because it happens before any call is made.

  Background:
    Given a freshly built sigillum binary
    And an empty working directory

  Scenario: A message for a different certificate is refused without touching the key service
    Given a published certificate
    And a report encrypted to somebody else's certificate
    When I decrypt the report
    Then it fails saying the message is addressed elsewhere
    And no key service was contacted

  Scenario: A damaged report is refused rather than half-read
    Given a published certificate
    And a report that is not an OpenPGP message
    When I decrypt the report
    Then it fails saying the message is malformed

  Scenario: A certificate with no encryption subkey is rejected up front
    Given a signing-only certificate
    And a report encrypted to somebody else's certificate
    When I decrypt the report
    Then it fails saying there is no encryption subkey

  Scenario: A certificate whose encryption subkey is RSA is rejected up front
    Given a certificate whose encryption subkey is RSA
    And a report encrypted to somebody else's certificate
    When I decrypt the report
    Then it fails saying there is no encryption subkey

  Scenario: The certificate is required
    When I decrypt a report without naming a certificate
    Then it fails naming the missing flag "--certificate"

  Scenario: An unknown backend lists the ones that exist
    Given a published certificate
    When I decrypt the report with backend "does-not-exist"
    Then it fails listing "aws-kms" as available

  Scenario: Assembling a certificate demands a fixed creation time
    When I assemble a certificate without a creation time
    Then it fails naming the missing flag "--created"
    And it explains that the time is part of the certificate's identity
