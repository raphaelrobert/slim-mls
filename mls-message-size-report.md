# SlimMLS message size estimates for a 100-member group

Date: 2026-04-28

This report estimates TLS-encoded wire sizes for SlimMLS Welcomes and SlimMLS
public commits with update paths in a 100-member group. It uses the
optimizations described in `draft-robert-mls-slim.md`: SlimWelcomes with
per-recipient secrets, plaintext GroupInfo supplied by a stateful DS,
SlimUpdatePath split delivery, hash references for large objects, Large Object
Carriers, cached unchanged signature keys and credentials, and delayed fetching
of large objects that are not needed immediately.

## Sources

- SlimMLS local draft: `draft-robert-mls-slim.md`
- MLS RFC 9420: https://datatracker.ietf.org/doc/html/rfc9420
- MLS PQ ciphersuite draft, current revision checked here:
  `draft-ietf-mls-pq-ciphersuites-04`, published 2026-03-19:
  https://datatracker.ietf.org/doc/html/draft-ietf-mls-pq-ciphersuites-04
- HPKE PQ draft for KEM public key and KEM output sizes:
  https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04
- FIPS 203 for ML-KEM object sizes:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- FIPS 204 for ML-DSA public key and signature sizes:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

## Ciphersuites

The non-PQ baseline is the MLS 1.0 MTI ciphersuite:

- `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`

For "ML-KEM768 and Ed25519", the current PQ MLS draft does not define a pure
ML-KEM768 plus Ed25519 ciphersuite. The matching draft ciphersuites use the
hybrid KEM `MLKEM768X25519` with Ed25519. I used the AES-128/SHA-256 variant
closest to the MTI ciphersuite:

- `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`

For ML-KEM1024 and ML-DSA87, I used:

- `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`

## Assumptions

- The group has 100 members after the Welcome add.
- The ratchet tree has 100 non-blank leaves and 99 non-blank parent nodes.
- Parent `unmerged_leaves` vectors are empty.
- The Welcome is delivered to one new member. The DS reduces
  `SlimWelcome.secrets` to one `SlimEncryptedGroupSecrets` entry and uses the
  `leaf_node_index` recipient identifier.
- The Welcome `group_info` is the plaintext variant, populated by the DS.
- The Welcome tree has one commit-sourced leaf for the committer and 99 minimal
  key-package-sourced leaves.
- The commit is a member PublicMessage commit with an update path and no
  proposals. This models a self-update commit.
- The sender's signature public key and credential do not change in the commit.
  Therefore the sender does not upload them in the commit carrier.
- The commit uses the SlimMLS single-signature construction: the framing
  signature is absent, the confirmation tag is present, and the commit leaf
  contains an `OuterUpdateHash` component.
- The `app_data_dictionary` TLS syntax is not yet specified in the SlimMLS
  draft. I modeled the required `OuterUpdateHash` as one dictionary component:
  `uint16 component_id; opaque component_data<V>;`, wrapped in one LeafNode
  extension. This is only a few bytes of overhead.
- Group IDs are 16 bytes. `authenticated_data` is empty.
- Credentials are basic credentials with 16-byte identities:
  `CredentialType` plus `opaque identity<V>` = 19 encoded bytes.
- No GREASE, PSKs, `external_pub`, `required_capabilities`, application
  extensions, or lower-layer DS transport framing is counted.
- MLS `V` vectors use RFC 9420's 1/2/4-byte variable-length vector prefix.
- AES-GCM tag size is 16 bytes.

The commit update path height depends on the sender leaf in a left-balanced
100-leaf tree. For leaves 0 through 95 the direct path has 7 parent nodes; for
the rightmost four leaves it has 4. The tables use the common/worst case of 7
path nodes.

## Summary

All numbers are bytes. "Message" is the MLSMessage carrying SlimWelcome or
SlimPublicCommitMessage. "Carrier" is the raw SlimMLS LargeObjectCarrier
payload, without any application or DS wrapper.

| Ciphersuite | Welcome message | Welcome carrier | Welcome total | DS-to-member commit message | DS-to-member commit carrier | DS-to-member commit total | Sender-to-DS commit total | Commit aggregate for 99 recipients |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | 26,840 | 5,206 | 32,046 | 632 | 87 | 719 | 1,674 | 72,855 |
| `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` | 27,929 | 5,206 | 33,135 | 632 | 1,176 | 1,808 | 18,777 | 197,769 |
| `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` | 497,320 | 261,308 | 758,628 | 5,435 | 1,641 | 7,076 | 29,747 | 730,271 |

`Commit aggregate for 99 recipients` is:

```text
sender-to-DS commit total + 99 * DS-to-member commit total
```

## Object sizes used

These are encoded object sizes, including MLS vector length prefixes where
applicable.

| Ciphersuite | Hash/ref size | HPKE public key | Welcome HPKECiphertext | UpdatePath HPKECiphertext | Signature public key | Signature |
|---|---:|---:|---:|---:|---:|---:|
| MTI X25519/Ed25519 | 33 | 33 | 119 | 82 | 33 | 66 |
| MLKEM768X25519/Ed25519 | 33 | 1,218 | 1,208 | 1,171 | 33 | 66 |
| MLKEM1024/ML-DSA87 | 49 | 1,570 | 1,688 | 1,636 | 2,594 | 4,629 |

Notes:

- A 32-byte hash reference encodes to 33 bytes. A 48-byte hash reference
  encodes to 49 bytes.
- Ed25519 public keys are 32 bytes and Ed25519 signatures are 64 bytes.
- ML-DSA87 public keys are 2,592 bytes and signatures are 4,627 bytes.
- `MLKEM768X25519` uses HPKE `Npk = 1216` and `Nenc = 1120`.
- `ML-KEM-1024` uses HPKE `Npk = 1568` and `Nenc = 1568`.

## Welcome: what is sent

The delivered Welcome is an MLSMessage with SlimMLS wire format
`mls_slim_welcome`. It contains:

- `cipher_suite`: 2 bytes.
- `secrets`: one `SlimEncryptedGroupSecrets`, because the DS strips all other
  recipients. It uses `leaf_node_index`, so the recipient identifier is 5 bytes
  instead of a hash reference. The encrypted payload is `GroupSecrets` containing
  a joiner secret, a path secret, and an empty PSK list.
- `group_info`: present, plaintext. This avoids encrypting the whole GroupInfo
  and lets the DS deliver a leaf-index-targeted secret.
- `GroupInfo`: GroupContext with the `slim_mls` extension, the normal
  confirmation tag and GroupInfo signature, and one `slim_ratchet_tree`
  extension.
- `slim_ratchet_tree`: 100 SlimLeafNodes and 99 SlimParentNodes. Slim nodes
  contain references to HPKE public keys, signature public keys, and
  credentials, not the objects themselves.
- Carrier: 100 signature public keys and 100 basic credentials. HPKE public
  keys are not sent in the Welcome carrier because the joiner can validate the
  slim tree and GroupInfo using references and can fetch HPKE public keys later
  when it needs to encrypt to a resolution node.

The large ML-DSA87 Welcome is dominated by the 100 ML-DSA87 LeafNode signatures
inside the slim tree and the 100 ML-DSA87 signature public keys in the carrier.
SlimMLS can replace signature public keys with references inside GroupInfo, but
it cannot remove the LeafNode signatures themselves.

## Commit: what is sent

The sender uploads an MLSMessage with SlimMLS wire format
`mls_slim_public_commit`. It contains:

- `SlimCommitFramedContent`: group id, epoch, member sender, empty
  authenticated data, content type `commit`, and a `SlimCommit`.
- `SlimCommit`: empty proposal list and the committer's new SlimLeafNode.
- `SlimCommitFramedContentAuthData`: absent framing signature plus the normal
  confirmation tag.
- PublicMessage membership tag.
- `SlimUpdatePath`: 7 path nodes in this 100-member tree case. Sender-to-DS
  upload has one HPKECiphertextRef per path node. DS-to-member delivery keeps
  all 7 HPKEPublicKeyRefs but reduces HPKECiphertextRefs to the one ciphertext
  the recipient needs.
- Sender-to-DS carrier: 8 HPKE public keys, namely the new leaf key plus 7 path
  node keys, and 7 HPKE ciphertexts.
- DS-to-member carrier: one HPKE ciphertext. It omits unchanged signature public
  key and credential objects, and it omits HPKE public keys that the recipient
  does not need immediately.

This is where the DS optimization matters most. The slim signed commit message
is identical for the MTI and MLKEM768X25519 Ed25519 ciphersuites; only the
carrier grows because the HPKE ciphertext and path public keys are larger. For
ML-KEM1024 with ML-DSA87, the message itself is larger because the commit
contains a new ML-DSA87-signed SlimLeafNode.

## Sensitivity

The estimates are exact for the assumptions above, but they are not universal
MLS constants. The largest variables are:

- X.509 credentials instead of 16-byte basic credentials.
- Cached signature public keys or credentials on the joining client.
- More than one new member in a Welcome.
- Additional GroupInfo, GroupContext, or LeafNode extensions.
- A sender in one of the rightmost four leaves of a 100-leaf left-balanced tree,
  where the update path has 4 nodes instead of 7.
- A commit that rotates the signature key. That disables the single-signature
  optimization and requires sending the new signature public key, and likely a
  credential, in the carrier.

