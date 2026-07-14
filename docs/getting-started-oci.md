# Getting Started with OCI KMS

This guide shows how to configure Oracle Cloud Infrastructure (OCI) Vault Key Management and use it with `crypt`.

## Prerequisites

You need an OCI tenancy, an OCI CLI/SDK configuration, and permission to use a key in a vault. For API-key authentication, create `~/.oci/config` with the OCI CLI:

```console
oci setup config
```

`crypt` uses the `DEFAULT` profile unless `--profile` or `OCI_CLI_PROFILE` selects another profile. Use `--config-file` when the configuration is stored outside `~/.oci/config`.

## IAM policy

The user group or workload principal needs permission to use keys. A tenancy administrator can start with a policy such as:

```text
Allow group CryptUsers to use keys in compartment Security
```

For an instance or resource principal, put the resource in a dynamic group and grant that dynamic group equivalent access:

```text
Allow dynamic-group CryptWorkloads to use keys in compartment Security
```

Restrict the compartment, group, and permissions to your deployment. See Oracle's [Vault IAM policy documentation](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/usingkeys.htm#Required_IAM_Policy) for more granular policies.

## Create a vault and key

In the OCI Console:

1. Open **Identity & Security**, then **Vault**.
2. Create or select a vault in the target compartment.
3. Create a master encryption key. `AES` with a 256-bit key is suitable for the default `AES_256_GCM` algorithm.
4. Copy the key OCID from the key details page.

OCI also supports RSA keys with `RSA_OAEP_SHA_256` or `RSA_OAEP_SHA_1`. When a rotated RSA key requires a specific key version, pass its OCID with `--key-version`.

## Find the crypto endpoint

Open the vault details page and copy its **Cryptographic Endpoint**. It has a form similar to:

```text
https://example-prefix-crypto.kms.ca-toronto-1.oraclecloud.com
```

The cryptographic endpoint is the per-vault data-plane endpoint. It is not the regional management endpoint. Oracle documents the distinction in [Encrypting Data](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/usingkeys_topic-To_encrypt_data_by_using_your_Vault_master_encryption_key.htm).

For shorter examples, set:

```console
export OCI_CRYPT_KEY_ID='ocid1.key.oc1...'
export OCI_CRYPT_CRYPTO_ENDPOINT='https://example-prefix-crypto.kms.ca-toronto-1.oraclecloud.com'
```

## Encryption

### stdin

```console
echo "top secret" | crypt encrypt oci --out file.enc
```

Without the environment variables, provide the values explicitly:

```console
echo "top secret" | crypt encrypt oci \
    --out file.enc \
    --key-id ocid1.key.oc1... \
    --crypto-endpoint https://example-prefix-crypto.kms.ca-toronto-1.oraclecloud.com
```

### Single file

```console
crypt encrypt oci \
    --in file.txt \
    --out file.enc \
    --key-id ocid1.key.oc1... \
    --crypto-endpoint https://example-prefix-crypto.kms.ca-toronto-1.oraclecloud.com
```

### Files in a directory

```console
crypt encrypt oci \
    --indir to-encrypt \
    --outdir encrypted \
    --key-id ocid1.key.oc1... \
    --crypto-endpoint https://example-prefix-crypto.kms.ca-toronto-1.oraclecloud.com
```

Encrypted directory entries use the `.crypt` extension by default.

## Decryption

`crypt` stores the key OCID, key version, crypto endpoint, and algorithm in a metadata header. Authentication data is never stored in that header. Therefore, ciphertext produced by `crypt` normally needs only an authentication configuration at decrypt time:

```console
crypt decrypt oci --in file.enc --out file.dec
```

Explicit key, key-version, endpoint, or algorithm flags override header values. This is useful after a key or endpoint migration.

### Headerless OCI ciphertext

For raw ciphertext bytes produced outside `crypt`, the key and crypto endpoint are required:

```console
crypt decrypt oci \
    --in raw-ciphertext.bin \
    --out file.dec \
    --key-id ocid1.key.oc1... \
    --crypto-endpoint https://example-prefix-crypto.kms.ca-toronto-1.oraclecloud.com
```

### Files in a directory

```console
crypt decrypt oci --indir encrypted --outdir decrypted
```

The command scans `.crypt` files and removes that extension in the destination directory.

## Authentication types

Select authentication with `--auth` or `OCI_CLI_AUTH`:

- `api_key` (default) reads an OCI configuration profile. Use `--profile` and optionally `--config-file`.
- `security_token` reads a session-token profile, such as one created by `oci session authenticate`.
- `instance_principal` uses the compute instance principal and does not read API keys from a profile.
- `resource_principal` uses the resource-principal environment supplied to supported OCI workloads such as Functions.

Examples:

```console
crypt encrypt oci --auth instance_principal \
    --key-id ocid1.key.oc1... \
    --crypto-endpoint https://example-prefix-crypto.kms.ca-toronto-1.oraclecloud.com \
    --in file.txt --out file.enc

crypt decrypt oci --auth resource_principal --in file.enc --out file.dec
```

## Template functions

The `encryptOCI` and `decryptOCI` functions use API-key profile authentication:

```gotemplate
{{ "top secret" | encryptOCI "ocid1.key.oc1..." "https://example-prefix-crypto.kms.ca-toronto-1.oraclecloud.com" "DEFAULT" }}
```

Header metadata makes the key and endpoint optional for decryption:

```gotemplate
{{ .ciphertext | decryptOCI "" "" "DEFAULT" }}
```

For binary-safe template output and better compression, combine encryption with `gzip` and `b64enc`, and reverse those operations with `b64dec` and `ungzip` when decrypting.

## Plaintext size limits

As verified on July 14, 2026, Oracle's current [Encrypt API model](https://docs.oracle.com/en-us/iaas/tools/go/latest/keymanagement/index.html#EncryptDataDetails) and [OCI CLI encrypt reference](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/kms/crypto/encrypt.html) do **not** publish a fixed maximum plaintext size. The 4,096-character limit shown on those pages applies to optional associated data, not plaintext. Do not assume the 4 KiB AWS KMS limit applies to OCI.

RSA OAEP payload capacity is smaller and depends on the RSA key size and selected hash algorithm. OCI validates the request against the actual key. `crypt` intentionally performs no client-side size check for any algorithm because that could reject requests Oracle accepts or duplicate key-specific service rules.

If OCI rejects an encryption request for its size, `crypt` preserves the service error and adds a hint to gzip the input or use envelope encryption. Gzip can help small text payloads; for general or large files, use envelope encryption with a generated data-encryption key. Envelope encryption is not yet implemented by `crypt`.
