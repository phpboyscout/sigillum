# sigillum

**Standalone artefact signing CLI.** Produce and publish signatures over release
artefacts: OpenPGP for checksum manifests, minisign for the artefacts themselves.
The private key never leaves your KMS, HSM or PEM file, and nothing about it cares
what language your project is written in.

> **This is a read-only mirror. The canonical repository is on GitLab:**
> **https://gitlab.com/phpboyscout/sigillum**
>
> Issues and merge requests are handled there.

## Installing

The module path is the GitLab one:

```
go install gitlab.com/phpboyscout/sigillum@latest
```

`go install github.com/phpboyscout/sigillum` will not work. The mirror is here
for browsing and reference only.

Binaries for each release are published on the
[GitLab releases page](https://gitlab.com/phpboyscout/sigillum/-/releases),
signed with the key documented below.

## Documentation

Full documentation: **https://sigillum.phpboyscout.uk**

Sixteen posts on why release signing is shaped this way, including the
seven-part walkthrough from a laptop key to keyless CI signing:
[Signing your releases](https://phpboyscout.uk/topics/signing/).
