module gitlab.com/phpboyscout/sigillum

go 1.27.1

tool (
	gitlab.com/phpboyscout/go-tool-base/cmd/changelog
	gitlab.com/phpboyscout/go-tool-base/cmd/docs
)

require (
	github.com/ProtonMail/go-crypto v1.4.1
	github.com/cucumber/godog v0.16.0
	github.com/spf13/afero v1.15.0
	github.com/spf13/cobra v1.10.2
	gitlab.com/phpboyscout/go-tool-base v0.45.3
	gitlab.com/phpboyscout/go/encryption v0.2.1
	gitlab.com/phpboyscout/go/encryption-aws-kms v0.3.1
	gitlab.com/phpboyscout/go/errorhandling v0.5.1
	gitlab.com/phpboyscout/go/forge-gitlab v0.24.0
	gitlab.com/phpboyscout/go/signing v0.8.2
	gitlab.com/phpboyscout/go/signing-aws-kms v0.6.1
	gitlab.com/phpboyscout/go/signing-cli v0.6.1
)

require (
	charm.land/bubbles/v2 v2.2.1 // indirect
	charm.land/bubbletea/v2 v2.0.9 // indirect
	charm.land/glamour/v2 v2.0.1 // indirect
	charm.land/huh/v2 v2.0.3 // indirect
	charm.land/lipgloss/v2 v2.0.6 // indirect
	charm.land/log/v2 v2.0.1 // indirect
	dario.cat/mergo v1.0.2 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/alecthomas/chroma/v2 v2.27.0 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aws/aws-sdk-go-v2 v1.43.7 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.38 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.37 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.38 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.38 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.38 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.39 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.38 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.55.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.5.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.33.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.38.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.45.7 // indirect
	github.com/aws/smithy-go v1.27.8 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.6.1 // indirect
	github.com/catppuccin/go v0.3.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/keygen v0.5.4 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20260910203606-6c9e17dc7a16 // indirect
	github.com/charmbracelet/x/ansi v0.11.8 // indirect
	github.com/charmbracelet/x/exp/ordered v0.1.0 // indirect
	github.com/charmbracelet/x/exp/slice v0.0.0-20260913004009-c615ff2f7805 // indirect
	github.com/charmbracelet/x/exp/strings v0.1.0 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/cli/browser v1.3.0 // indirect
	github.com/cli/oauth v1.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/cucumber/gherkin/go/v42 v42.0.0 // indirect
	github.com/cucumber/messages/go/v34 v34.2.0 // indirect
	github.com/cyphar/filepath-securejoin v0.7.0 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dlclark/regexp2/v2 v2.8.0 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.1 // indirect
	github.com/go-git/go-git/v5 v5.19.2 // indirect
	github.com/go-logfmt/logfmt v0.6.1 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-memdb v1.3.5 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/invopop/jsonschema v0.14.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.6.0 // indirect
	github.com/klauspost/compress v1.19.1 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/leodido/go-conventionalcommits v0.13.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.1 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-runewidth v0.0.30 // indirect
	github.com/microcosm-cc/bluemonday v1.0.27 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/onsi/gomega v1.42.1 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/pelletier/go-toml/v2 v2.4.3 // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/shirou/gopsutil/v4 v4.26.7 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/skeema/knownhosts v1.3.3 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xo/terminfo v1.2.0 // indirect
	github.com/yuin/goldmark v1.8.6 // indirect
	github.com/yuin/goldmark-emoji v1.0.6 // indirect
	github.com/zalando/go-keyring v0.2.8 // indirect
	gitlab.com/gitlab-org/api/client-go/v2 v2.64.0 // indirect
	gitlab.com/phpboyscout/go/authn v0.2.3 // indirect
	gitlab.com/phpboyscout/go/awsclient v0.1.0 // indirect
	gitlab.com/phpboyscout/go/browser v0.2.2 // indirect
	gitlab.com/phpboyscout/go/changelog v0.4.0 // indirect
	gitlab.com/phpboyscout/go/chat v0.24.0 // indirect
	gitlab.com/phpboyscout/go/clientlifecycle v0.2.0 // indirect
	gitlab.com/phpboyscout/go/config v0.18.0 // indirect
	gitlab.com/phpboyscout/go/config-afero v0.1.11 // indirect
	gitlab.com/phpboyscout/go/controls v0.7.0 // indirect
	gitlab.com/phpboyscout/go/credentials v0.3.2 // indirect
	gitlab.com/phpboyscout/go/errors v0.3.0 // indirect
	gitlab.com/phpboyscout/go/features v0.1.0 // indirect
	gitlab.com/phpboyscout/go/forge v0.31.0 // indirect
	gitlab.com/phpboyscout/go/httpclient v0.2.3 // indirect
	gitlab.com/phpboyscout/go/observability v0.3.2 // indirect
	gitlab.com/phpboyscout/go/output v0.2.2 // indirect
	gitlab.com/phpboyscout/go/redact v0.2.2 // indirect
	gitlab.com/phpboyscout/go/regexutil v0.2.2 // indirect
	gitlab.com/phpboyscout/go/tls v0.2.2 // indirect
	gitlab.com/phpboyscout/go/transit v0.2.3 // indirect
	gitlab.com/phpboyscout/go/transport v0.6.2 // indirect
	gitlab.com/phpboyscout/go/yamldoc v0.6.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/bridges/otelslog v0.20.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.71.0 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.22.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.46.0 // indirect
	go.opentelemetry.io/otel/log v0.22.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/sdk v1.46.0 // indirect
	go.opentelemetry.io/otel/sdk/log v0.22.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.6 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260917231906-eeb232e0883d // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260917231906-eeb232e0883d // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
