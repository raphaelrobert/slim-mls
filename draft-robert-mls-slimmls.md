---
title: "SlimMLS"
abbrev: "SlimMLS"
category: info

docname: draft-robert-mls-slimmls-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: Messaging Layer Security
keyword:
 - mls
 - post-quantum
 - bandwidth
 - storage
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "raphaelrobert/draft-robert-mls-slimmls"

author:
 -
    fullname: Raphael Robert
    organization: Phoenix R&D
    email: ietf@raphaelrobert.com
 -
    fullname: Konrad Kohbrok
    organization: Phoenix R&D
    email: konrad@ratchet.ing

normative:
  RFC9420:

informative:
  I-D.ietf-mls-partial:
  SAIK:
    title: "Server-Aided Continuous Group Key Agreement"
    author:
      - ins: J. Alwen
      - ins: D. Hartmann
      - ins: E. Kiltz
      - ins: M. Mularczyk
    date: 2022
    seriesinfo:
      "ACM CCS": "2022, pp. 69-82"
    target: https://eprint.iacr.org/2021/1456

...

--- abstract

This document defines SlimMLS, an extension to the Messaging Layer Security
(MLS) protocol that reduces the wire and per-client storage overhead of MLS
groups and makes MLS more flexible in server assisted deployments. SlimMLS's
main use-case is for groups with post-quantum ciphersuites. SlimMLS replaces
large objects like HPKE public keys, signature public keys, credentials and HPKE
ciphertexts with hash references. The large objects themselves are fetched by or
distributed by clients as needed. SlimMLS also defines SlimWelcomes, which apply
the partial-commit construction to Welcome messages so that recipients need only
download the HPKE ciphertext intended for them.

--- middle

# Introduction

Post-quantum (PQ) signature and KEM primitives have substantially larger keys,
ciphertexts, and signatures than their classical counterparts. In an MLS group
{{!RFC9420}} this manifests as significantly larger LeafNodes, parent nodes,
Welcomes, and Commits. The blow-up is felt both on the wire and in client
storage.

SlimMLS reduces this overhead by applying a single uniform technique: wherever a
large object appears inside a structure that is signed or fed into the MLS
transcript hash, it is replaced by a hash reference to that object. The object
itself is transported alongside the signed structure. Because the binding to the
signed structure is preserved by the hash, an untrusted Delivery Service (DS)
can selectively fan out large objects to the clients that need them, omit
objects a client already has, or rewrite the carrier without compromising
authenticity. In turn, clients can selectively fetch objects that they are
missing.

This pattern is not new in MLS: {{!RFC9420}} already uses RefHash-based
references such as KeyPackageRef and ProposalRef. SlimMLS generalizes
the mechanism.

[\[TODO: quantify wire and storage savings for representative PQ
ciphersuites once the specification stabilizes.\]\]


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the TLS presentation language and notation of
{{!RFC9420}}. Familiarity with MLS {{!RFC9420}} is assumed.


# Overview

A SlimMLS group is an MLS group whose GroupContext carries the `slim_mls`
extension ({{slim-mls-extension}}). In such a group:

- Every place where {{!RFC9420}} embeds one of the large object types
  enumerated in {{ref-types}} inside a signed or transcript-hashed
  structure is replaced with a hash reference of the corresponding type.
- Every slim message carries, in addition to the signed structure, an
  unauthenticated carrier ({{large-object-carrier}}) holding the large
  objects each recipient needs.

# Reference Computation {#ref-types}

All new references are computed in the same style as KeyPackageRef in
{{Section 5.2 of !RFC9420}}, i.e., using RefHash instantiated with the
group's ciphersuite hash function and a label unique to the referenced
object type. Inputs are TLS-encoded per {{!RFC9420}}.

The following reference types are defined:

| Object type        | Reference type        | RefHash label                        |
|--------------------|-----------------------|--------------------------------------|
| HPKEPublicKey      | HPKEPublicKeyRef      | "MLS 1.0 SlimMLS HPKEPublicKey"      |
| SignaturePublicKey | SignaturePublicKeyRef | "MLS 1.0 SlimMLS SignaturePublicKey" |
| Credential         | CredentialRef         | "MLS 1.0 SlimMLS Credential"         |
| HPKECiphertext     | HPKECiphertextRef     | "MLS 1.0 SlimMLS HPKECiphertext"     |

Each reference is `opaque<V>` where `V` is the output length of the
ciphersuite hash function.

# SlimMLS Structs {#slim-structs}

For every {{!RFC9420}} struct that embeds one or more of the large object types
listed in {{ref-types}}, SlimMLS defines a corresponding "Slim*" struct that is
identical to the original except that each occurrence of a large object is
replaced by the reference type from {{ref-types}} and that each occurrence of a
struct for which there exists a Slim equivalent is replaced by that equivalent.

The exception to the rule is the Welcome struct, which is simply replaced by the
SlimWelcome struct as defined in {{slim-welcome}}.

In a SlimMLS group, the slim struct is sent on the wire wherever {{!RFC9420}}
would specify the original struct. Validation of {{!RFC9420}} apply in the same
way. References are only replaced by the corresponding large objects if
functionally necessary (e.g. to verify a signature or encrypt a ciphertext).

The {{!RFC9420}} structs affected, the large objects they embed, and the
SlimMLS replacements are listed below. Structs whose only embedded large
objects appear via a nested struct (e.g., proposals that carry a
LeafNode or KeyPackage) inherit slim variants implicitly via the slim
nested struct.

| RFC 9420 struct           | Embedded large object(s)                                  | SlimMLS replacement(s)                              |
|---------------------------|-----------------------------------------------------------|-----------------------------------------------------|
| LeafNode                  | HPKEPublicKey, SignaturePublicKey, Credential             | HPKEPublicKeyRef, SignaturePublicKeyRef, CredentialRef |
| ParentNode                | HPKEPublicKey                                             | HPKEPublicKeyRef                                    |
| KeyPackage                | HPKEPublicKey (init_key), LeafNode                        | HPKEPublicKeyRef; SlimLeafNode                     |
| UpdatePathNode            | HPKEPublicKey; HPKECiphertext (vector)  | HPKEPublicKeyRef; HPKECiphertextRef (vector)            |
| UpdatePath                | LeafNode; UpdatePathNode (vector)                             | SlimLeafNode; SlimUpdatePathNode             |
| Add proposal              | KeyPackage                                                | SlimKeyPackage                                     |
| Update proposal           | LeafNode                                                  | SlimLeafNode                                       |
| ratchet_tree extension    | LeafNode, ParentNode                                      | SlimLeafNode, SlimParentNode                      |

The exact TLS presentation of each slim struct is obtained by mechanical
substitution against {{!RFC9420}} and is not repeated here.

\[\[TODO: provide explicit TLS presentations for each slim variant in a
later revision.\]\]


# Large Object Carrier {#large-object-carrier}

A client sending a SlimMLS struct over the wire MAY also send a
LargeObjectCarrier struct that contains a subset of the large structs referenced
by the SlimMLS struct.

For each `*Ref` type that appears in the signed structure, the
LargeObjectCarrier contains a vector of the corresponding large objects:

~~~
struct {
  HPKEPublicKey      hpke_public_keys<V>;
  SignaturePublicKey signature_public_keys<V>;
  Credential         credentials<V>;
  HPKECiphertext     hpke_ciphertexts<V>;
} LargeObjectCarrier;
~~~

The carrier is NOT part of the signed structure. The DS MAY add, remove,
reorder, or substitute entries on a per-recipient basis, e.g., to omit objects
the recipient already has cached, or to distribute partial-commit ciphertexts.
The DS MAY reject a message based on a missing LargeObjectCarrier or on a
LargeObjectCarrier that is missing the large objects that clients will need to
process a message.

On receipt, a client:

1. Computes the reference of every entry in the carrier under the
   appropriate label.
2. For every `*Ref` appearing in the signed structure, locates the
   matching object either in the carrier or in its local cache.
3. If any required object is missing, the client MUST request it from the DS via
   an application-specific mechanism, or drop the message.

# SlimWelcome {#slim-welcome}

SlimWelcome makes two changes relative to the {{!RFC9420}} Welcome:

1. The per-recipient EncryptedGroupSecrets is replaced by a
   SlimEncryptedGroupSecrets ({{slim-egs}}), which permits the recipient to be
   identified either by KeyPackageRef (as in {{!RFC9420}}) or by leaf index.
2. The `encrypted_group_info` field is replaced by an
   `optional<WelcomeGroupInfo>` ({{welcome-group-info}}), where
   WelcomeGroupInfo is a tagged union over the {{!RFC9420}}
   encrypted form and a plaintext form.

With the exception of changes described in this section, SlimWelcomes are
processed just like regular Welcome messages.

~~~
struct {
  CipherSuite                cipher_suite;
  SlimEncryptedGroupSecrets  secrets<V>;
  optional<WelcomeGroupInfo> group_info;
} SlimWelcome;
~~~

## Sender and DS Behavior

The sender MUST construct `SlimWelcome.secrets` to contain one
SlimEncryptedGroupSecrets for every recipient it intends to add, in
the same order it would use under {{!RFC9420}}.

The DS MAY remove entries from `SlimWelcome.secrets` on a per-recipient basis,
e.g., to deliver to each recipient only its own entry.

If the sender omits the `group_info` field (presence octet 0), the DS MUST
populate it with a WelcomeGroupInfo before delivering the SlimWelcome to a
recipient ({{welcome-group-info}}).

## SlimEncryptedGroupSecrets {#slim-egs}

SlimEncryptedGroupSecrets extends the {{!RFC9420}}
EncryptedGroupSecrets to allow either of two recipient identifiers:

~~~
enum {
  reserved(0),
  key_package_ref(1),
  leaf_node_index(2),
  (255)
} RecipientIdentifierType;

struct {
  RecipientIdentifierType recipient_type;
  select (SlimEncryptedGroupSecrets.recipient_type) {
    case key_package_ref:
      KeyPackageRef new_member;
    case leaf_node_index:
      uint32 leaf_node_index;
  };
  HPKECiphertext encrypted_group_secrets;
} SlimEncryptedGroupSecrets;
~~~

A recipient locates the entry intended for it by matching either its own
KeyPackageRef or its leaf in the group's ratchet tree via the leaf index.

## WelcomeGroupInfo {#welcome-group-info}

WelcomeGroupInfo is a tagged union over two presentations of the
GroupInfo: the encrypted form used by {{!RFC9420}} or a plaintext
form:

~~~
enum {
  reserved(0),
  encrypted(1),
  plaintext(2),
  (255)
} WelcomeGroupInfoType;

struct {
  WelcomeGroupInfoType info_type;
  select (WelcomeGroupInfo.info_type) {
    case encrypted:
      opaque encrypted_group_info<V>;
    case plaintext:
      GroupInfo group_info;
  };
} WelcomeGroupInfo;
~~~

The `encrypted` variant is identical to the `encrypted_group_info`
field of the {{!RFC9420}} Welcome, encrypted under a key derived from
the joiner secret. The `plaintext` variant carries the GroupInfo in
the clear.

The outer `optional<WelcomeGroupInfo>` in the SlimWelcome additionally allows
the sender to omit the GroupInfo. This mode is intended for server-assisted
deployments where the sender is already providing a (partial) GroupInfo
alongside the commit that adds the new member(s)to the group.

A recipient that receives a SlimWelcome whose `group_info` field is
absent MUST consider the SlimWelcome invalid.


# Wire Formats {#wire-formats}

SlimMLS introduces new WireFormat values only where a recipient cannot know
from context that SlimMLS framing is in use, which applies to SlimKeyPackages
and SlimWelcomes.

MLSMessage is correspondingly extended with the two new cases:

~~~
struct {
  ProtocolVersion version = mls10;
  WireFormat wire_format;
  select (MLSMessage.wire_format) {
    case mls_public_message:    PublicMessage  public_message;
    case mls_private_message:   PrivateMessage private_message;
    case mls_welcome:           Welcome        welcome;
    case mls_group_info:        GroupInfo      group_info;
    case mls_key_package:       KeyPackage     key_package;
    case mls_slim_welcome:      SlimWelcome    slim_welcome;
    case mls_slim_key_package:  SlimKeyPackage slim_key_package;
  };
} MLSMessage;
~~~

A SlimMLS-aware sender MAY use `mls_slim_key_package` for any SlimKeyPackage
publication and MUST use `mls_slim_welcome` for any SlimWelcome delivery in
the context of a group with the `slim_mls` extension.

# The slim_mls Extension {#slim-mls-extension}

SlimMLS is signaled by a GroupContext extension named `slim_mls`. Presence
of this extension in the GroupContext means that all wire formats within
the group use SlimMLS replacements.

# The slim_external_pub Extension {#slim-external-pub-extension}

The {{!RFC9420}} `external_pub` GroupInfo extension carries an
HPKEPublicKey that external joiners use when issuing an External
Init proposal ({{Section 12.4.3.2 of !RFC9420}}). SlimMLS defines a
`slim_external_pub` GroupInfo extension that conveys the same
information using an HPKEPublicKeyRef:

~~~
struct {
  HPKEPublicKeyRef external_pub_ref;
} SlimExternalPub;
~~~

In a SlimMLS group, the {{!RFC9420}} `external_pub` extension MUST NOT
be used. A sender that would include `external_pub` MUST instead
include the `slim_external_pub` extension, populated with the
reference to the relevant HPKEPublicKey. The actual public key is
resolved via the LargeObjectCarrier ({{large-object-carrier}}) or the
local cache, as for any other HPKEPublicKeyRef.


# Security Considerations

The signing and transcript-hashing rules of {{!RFC9420}} are preserved by
SlimMLS: every struct that was authenticated under {{!RFC9420}} remains
authenticated, with large objects bound through the collision-resistant hash
references defined in {{ref-types}}. The strength of the binding is therefore at
most the collision resistance of the ciphersuite hash.

The LargeObjectCarrier ({{large-object-carrier}}) is unauthenticated by design.
A Delivery Service or network attacker that withholds, modifies, or substitutes
carrier entries can only cause a recipient to fail to resolve a reference, which
is functionally equivalent to dropping the message, which the DS can already to
under {{!RFC9420}}. A recipient MUST verify that any object it consumes from the
carrier hashes (under the appropriate label and the ciphersuite hash) to the
corresponding `*Ref` in the signed structure before using that object for any
cryptographic operation.

Because the carrier is unauthenticated, an attacker can also include
unsolicited or malformed objects in it. Recipients MUST NOT treat the
carrier as authoritative metadata and MUST ignore objects whose hash does
not match any reference in the signed structure.

A client that caches resolved large objects across groups MUST index its
cache by the pair (ciphersuite hash function, reference value). The same
underlying object yields different reference values under different hash
functions, and a cached object MUST NOT be treated as authoritative
across ciphersuites whose hash functions differ.

SlimWelcome ({{slim-welcome}}) introduces two confidentiality changes
relative to the {{!RFC9420}} Welcome:

- When `WelcomeGroupInfo.info_type` is `plaintext`, the GroupInfo is visible to
  the DS and to anyone observing the SlimWelcome on the wire. This variant is
  appropriate only in deployments where the GroupInfo is not considered
  confidential with respect to those parties (e.g., where the DS already
  maintains group state).
- When `SlimWelcome.group_info` is absent (presence octet 0), the DS
  chooses which WelcomeGroupInfo a joiner ultimately receives.

In both cases authenticity is unchanged: the joiner MUST verify the
GroupInfo signature exactly as under {{!RFC9420}}, and a SlimWelcome
that reaches a recipient with `group_info` still absent MUST be
rejected ({{welcome-group-info}}).

# IANA Considerations

## SlimMLS MLS Extension Types

IANA is requested to add the following entries to the "MLS Extension
Types" registry defined in {{Section 17.3 of !RFC9420}}:

| Value | Name              | Message(s) | Recommended | Reference |
|-------|-------------------|------------|-------------|-----------|
| TBD   | slim_mls          | GC         | Y           | RFC XXXX  |
| TBD   | slim_external_pub | GI         | Y           | RFC XXXX  |

The "Message(s)" abbreviations are those used in {{Section 17.3 of
!RFC9420}}; "GC" denotes a GroupContext extension and "GI" denotes a
GroupInfo extension. RFC XXXX is to be replaced with the RFC number
assigned to this document upon publication.

## SlimMLS Wire Formats

IANA is requested to add the following entries to the "MLS Wire
Formats" registry defined in {{Section 17.2 of !RFC9420}}:

| Value | Name                  | Recommended | Reference |
|-------|-----------------------|-------------|-----------|
| TBD   | mls_slim_welcome      | Y           | RFC XXXX  |
| TBD   | mls_slim_key_package  | Y           | RFC XXXX  |


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
