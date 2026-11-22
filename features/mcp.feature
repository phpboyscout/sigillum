Feature: The MCP tool surface
  As someone pointing an agent at sigillum
  I want it to serve only tools that report state or read public material
  So that an agent cannot sign, decrypt, publish, mutate config or update the binary

  # The served list is compared exactly, so a new command fails this scenario
  # until someone decides whether to expose it (sigillum spec 0003).

  Background:
    Given a freshly built sigillum binary
    And an empty working directory

  Scenario: The catalogue holds exactly the read-mostly tools
    When I browse the MCP tool catalogue
    Then the catalogue lists exactly these tools:
      | sigillum_changelog           |
      | sigillum_config_list         |
      | sigillum_config_path         |
      | sigillum_config_validate     |
      | sigillum_doctor              |
      | sigillum_doctor_report       |
      | sigillum_keys_generate       |
      | sigillum_keys_generate-image |
      | sigillum_keys_minisign       |
      | sigillum_version             |

  Scenario Outline: A withheld command cannot be called over MCP
    When I call the MCP tool "<tool>"
    Then the MCP call is refused as unavailable

    Examples:
      | tool                     |
      | sigillum_sign            |
      | sigillum_sign_image      |
      | sigillum_keys_mint       |
      | sigillum_keys_rotate     |
      | sigillum_keys_publish    |
      | sigillum_keys_wkd        |
      | sigillum_decrypt         |
      | sigillum_certificate     |
      | sigillum_update          |
      | sigillum_config_get      |
      | sigillum_config_set      |
      | sigillum_config_trust    |

  Scenario: A withheld command still runs on the CLI
    Given an ed25519 key with a pem private half
    And a release artefact "app.tar.gz"
    When I sign that artefact as minisign for project "demo"
    Then the command succeeds

  Scenario: mcp stream refuses to serve
    When I run mcp stream
    Then the command fails
    And stderr mentions "mcp stream is withheld"
