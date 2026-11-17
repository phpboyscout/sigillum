---
title: Sign a container image
description: Sign a container image by digest with sigillum, push the signature to its registry in the forms cosign verifies, and check it with cosign verify, locally and in GitLab CI with an AWS KMS key.
date: 2026-11-17
tags: [how-to, container-images, cosign, sigstore, ecdsa, aws-kms, ci]
authors: [Matt Cockayne <matt@phpboyscout.uk>]
---

# Sign a container image

`sigillum sign image` signs an image by its digest and pushes the signature to
the image's own registry, as a cosign signature and as a Sigstore bundle.
`cosign verify --key` checks it, and so does any verifier that reads either
form. Nothing is uploaded to a transparency log, so verification runs with the
log check off.

## Prerequisites

- sigillum installed.
- An image already pushed, and its **digest** (`sha256:<hex>`). A tag is
  refused.
- Push access to the image's repository, because the signature is pushed
  beside it.
- cosign, to check the result.

## Find the digest to sign

Sign the digest the registry holds, not the one your local Docker reports.
They differ when you re-tag a multi-platform image: Docker keeps the upstream
index digest, while a push sends one platform's manifest under a different
digest. Signing the index digest then fails with a `404 Not Found` from the
registry.

Take the digest from the step that pushed the image:

```bash
docker buildx build --push --metadata-file meta.json -t "$IMAGE:$TAG" .
DIGEST=$(jq -r '."containerimage.digest"' meta.json)
```

Or ask the registry with `crane digest "$IMAGE:$TAG"`. Either way, sign
`"$IMAGE@$DIGEST"`.

## Sign with a local key (testing)

`keys generate-image` writes an ECDSA P-256 pair: `image.key` (unencrypted
PKCS#8, mode `0600`) and `image.pub`.

```bash
sigillum keys generate-image
sigillum sign image --backend local --key-id image.key "$IMAGE@$DIGEST"
```

On success it prints where each form went:

```
signature: localhost:5055/demo:sha256-0f49f331d9212aff11b932863be4eb01cdf962969aa86dab7d1ee21ac6f5f52b.sig
bundle: localhost:5055/demo@sha256:f2c5193031380955bab855af0bf92e731302a3dff5790bbcbaae11f368b543ff
```

Anyone who can read `image.key` can sign as you. Keep it to tests and local
registries.

## Sign with AWS KMS (production)

Use an asymmetric KMS key with key spec `ECC_NIST_P256` and key usage
`SIGN_VERIFY`. P-256 is the algorithm every image verifier surveyed accepts.

```bash
sigillum sign image \
    --backend aws-kms --kms-region eu-west-2 \
    --key-id alias/image-signing \
    "$IMAGE@$DIGEST"
```

Verifiers need the public half as PEM. KMS returns it as DER:

```bash
aws kms get-public-key --key-id alias/image-signing \
    --query PublicKey --output text | base64 -d > image.der
openssl pkey -pubin -inform DER -in image.der -out image.pub
```

## Registry credentials

Without flags, sigillum reads the Docker config, which `docker login` and
`crane auth login` write. To pass credentials explicitly, give the username as a
flag and the password on the first line of stdin. There is no password flag,
so the password never reaches shell history or the process list.

```bash
echo "$REGISTRY_PASSWORD" | sigillum sign image \
    --backend aws-kms --key-id alias/image-signing \
    --registry-username "$REGISTRY_USER" --registry-password-stdin \
    "$IMAGE@$DIGEST"
```

## Verify

```bash
cosign verify --key image.pub --insecure-ignore-tlog "$IMAGE@$DIGEST"
```

cosign warns that skipping the transparency log is insecure. That is expected,
because nothing was logged. A good signature lists the checks performed and
prints the signed claims. A wrong key fails with:

```
Error: no matching attestations: failed to verify signature: could not verify envelope: accepted signatures do not match threshold, Found: 0, Expected 1
```

## CI integration: GitLab

In a GitLab job, the job's own registry credentials can push the signature.
The job has to know the digest, so build and sign in the same job, or pass the
digest on from the build job as a dotenv artifact:

```yaml
sign-image:
  script:
    - docker buildx build --push --metadata-file meta.json
        -t "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" .
    - DIGEST=$(jq -r '."containerimage.digest"' meta.json)
    - echo "$CI_REGISTRY_PASSWORD" | sigillum sign image
        --backend aws-kms --key-id alias/image-signing
        --registry-username "$CI_REGISTRY_USER" --registry-password-stdin
        "$CI_REGISTRY_IMAGE@$DIGEST"
```

The AWS credentials come from the SDK's default chain, filled the same way as
for file signing. See
[CI integration: GitLab + AWS OIDC](sign-a-release-artefact.md#ci-integration-gitlab-aws-oidc).

## Related

- [`sign image` reference](../reference/cli/sign.md#sign-image): every flag and
  every refusal
- [`keys generate-image` reference](../reference/cli/keys.md#keys-generate-image)
- [What sigillum does not do](../explanation/what-sigillum-does-not-do.md)
