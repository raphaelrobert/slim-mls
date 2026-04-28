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

informative:
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
ciphertexts with hash references. The large objects themselves are obtained by
clients as needed, either from a message-specific carrier, a local cache, or an
application-specific fetch mechanism. SlimMLS also defines SlimWelcomes, which
apply the partial-commit construction to Welcome messages so that recipients
need only download the HPKE ciphertext intended for them.

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
itself can be transported alongside the signed structure, retrieved from a
cache, or fetched separately. Because the binding to the signed structure is
preserved by the hash, an untrusted Delivery Service (DS) can selectively fan out
large objects to the clients that need them, omit objects a client already has,
or rewrite a carrier without compromising authenticity. In turn, clients can
selectively fetch objects that they are missing.

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

- Every place where {{!RFC9420}} embeds an HPKEPublicKey, SignaturePublicKey,
  Credential, or HPKECiphertext inside a signed or transcript-hashed structure
  is replaced with a hash reference of the corresponding type.
- A slim message MAY be accompanied by an unauthenticated carrier
  ({{large-object-carrier}}) holding a subset of the large objects the recipient
  needs. Recipients can also resolve references from a local cache or through an
  application-specific fetch mechanism.

# Reference Computation {#ref-types}

All new references are computed in the same style as KeyPackageRef in
{{Section 5.2 of !RFC9420}}, i.e., using RefHash instantiated with the
group's ciphersuite hash function and a label unique to the referenced
object type. Inputs are TLS-encoded per {{!RFC9420}}.

The following reference types are defined:

| Referenced value   | Reference type        | RefHash label                        |
|--------------------|-----------------------|--------------------------------------|
| HPKEPublicKey      | HPKEPublicKeyRef      | "MLS 1.0 SlimMLS HPKEPublicKey"      |
| SignaturePublicKey | SignaturePublicKeyRef | "MLS 1.0 SlimMLS SignaturePublicKey" |
| Credential         | CredentialRef         | "MLS 1.0 SlimMLS Credential"         |
| HPKECiphertext     | HPKECiphertextRef     | "MLS 1.0 SlimMLS HPKECiphertext"     |
| SlimKeyPackage     | SlimKeyPackageRef     | "MLS 1.0 SlimMLS KeyPackage Reference" |

Each reference is `opaque<V>` where `V` is the output length of the
ciphersuite hash function.

For a SlimKeyPackageRef, the value input is the TLS-encoded SlimKeyPackage.
SlimKeyPackageRef is used to identify the recipient of a SlimWelcome; it is not
a large-object reference and has no corresponding LargeObjectCarrier entry.

# SlimMLS Structs {#slim-structs}

For every {{!RFC9420}} struct that embeds an HPKEPublicKey, SignaturePublicKey,
Credential, or HPKECiphertext, SlimMLS defines a corresponding "Slim*" struct
that is identical to the original except that each occurrence of a large object
is replaced by the reference type from {{ref-types}} and that each occurrence of
a struct for which there exists a Slim equivalent is replaced by that
equivalent.
Tree hashes and parent hashes are likewise computed over the slim encodings, so
the reference values stand in for the corresponding large objects in these
computations.

The exceptions to the rule are the Welcome, KeyPackage, and Commit structs,
which are replaced by the SlimWelcome struct ({{slim-welcome}}), the
SlimKeyPackage struct ({{slim-key-package}}), and the SlimCommit struct
({{slim-commit}}) respectively. As a consequence, the UpdatePath struct does
not appear in a SlimMLS group; its contents are split between SlimCommit
(which carries the committer's SlimLeafNode) and SlimUpdatePath (which
carries the path nodes).

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
| ParentHashInput           | HPKEPublicKey                                             | HPKEPublicKeyRef                                    |
| UpdatePathNode            | HPKEPublicKey; HPKECiphertext (vector)  | HPKEPublicKeyRef; HPKECiphertextRef (vector)            |
| Add proposal              | KeyPackage                                                | SlimKeyPackage                                     |
| Update proposal           | LeafNode                                                  | SlimLeafNode                                       |
| ratchet_tree extension    | LeafNode, ParentNode                                      | slim_ratchet_tree extension with SlimLeafNode, SlimParentNode |

The following slim tree structures are used in tree-hash and parent-hash
computations:

~~~
struct {
  HPKEPublicKeyRef encryption_key_ref;
  opaque           parent_hash<V>;
  uint32           unmerged_leaves<V>;
} SlimParentNode;

struct {
  HPKEPublicKeyRef encryption_key_ref;
  opaque           parent_hash<V>;
  opaque           original_sibling_tree_hash<V>;
} SlimParentHashInput;
~~~

SlimParentNode replaces ParentNode. SlimParentHashInput replaces the
ParentHashInput defined in {{Section 7.9 of !RFC9420}}.

The exact TLS presentation of each other slim struct is obtained by mechanical
substitution against {{!RFC9420}} and is not repeated here.

\[\[TODO: provide explicit TLS presentations for each slim variant in a
later revision.\]\]

# Large Object Carrier {#large-object-carrier}

A client sending a SlimMLS struct over the wire MAY also send a
LargeObjectCarrier struct that contains a subset of the large structs referenced
by the SlimMLS struct or by an associated unauthenticated structure such as
SlimUpdatePath ({{slim-commit}}). When a GroupInfo in a SlimMLS group contains
extensions with `*Ref` values, such as `slim_ratchet_tree`
({{slim-ratchet-tree-extension}}) or `slim_external_pub`
({{slim-external-pub-extension}}), the corresponding large objects can be
provided in a LargeObjectCarrier, from a local cache, or by an
application-specific fetch mechanism.

This document does not define a single MLSMessage wrapper for
LargeObjectCarrier. When a carrier is sent on the wire, its encoding,
multiplexing, and association with the SlimMLS message are provided by the
application or DS protocol using SlimMLS.

For each large-object reference type that appears in a slim structure or an
associated unauthenticated structure, the LargeObjectCarrier contains a vector
of the corresponding large objects:

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
The LargeObjectCarrier is optional in the SlimMLS wire protocol. The DS MAY
reject a message based on a missing LargeObjectCarrier, or on a
LargeObjectCarrier that is missing the large objects that clients will need to
process a message, if its local deployment policy requires senders to provide
those objects proactively.

On receipt, a client:

1. Computes the reference of every entry in the carrier under the
   appropriate label, if a carrier is present.
2. For every large-object `*Ref` that the client needs to process the slim
   structure or an associated unauthenticated structure, locates the matching
   object in the carrier, in its local cache, or by using an application-specific
   fetch mechanism.
3. If any required object is missing, the client MUST request it through an
   application-specific mechanism, for example from the DS, or drop the message.

# SlimKeyPackage {#slim-key-package}

SlimKeyPackage applies the slim reference replacement to KeyPackage and
additionally adopts the single-signature construction of
{{?I-D.kohbrok-mls-fewer-signatures}}: the signature around the KeyPackage is
omitted, and authenticity of the surrounding fields is provided by a hash
component placed in the SlimLeafNode that the SlimLeafNode's signature
already covers.

A SlimKeyPackage is partitioned into an OuterSlimKeyPackage (the fields of a
KeyPackage other than the LeafNode and signature) and a SlimLeafNode:

~~~
struct {
  ProtocolVersion  version;
  CipherSuite      cipher_suite;
  HPKEPublicKeyRef init_key_ref;
  Extension        extensions<V>;
} OuterSlimKeyPackage;

struct {
  OuterSlimKeyPackage outer_key_package;
  SlimLeafNode        leaf_node;
} SlimKeyPackage;
~~~

A SlimKeyPackage carries no outer signature. Authenticity of
`outer_key_package` is provided by an OuterKeyPackageHash component
({{outer-key-package-hash}}) placed in the SlimLeafNode's
`app_data_dictionary` extension, which is in turn covered by the
SlimLeafNode's signature.

The HPKEPublicKey corresponding to `init_key_ref`, together with any large
objects referenced by the SlimLeafNode, is resolved per
{{large-object-carrier}}.

## OuterKeyPackageHash component {#outer-key-package-hash}

~~~
struct {
  opaque outer_key_package_hash<V>;
} OuterKeyPackageHash;
~~~

`outer_key_package_hash` is the hash, under the SlimKeyPackage's ciphersuite
hash function, of the TLS-encoded `outer_key_package` of the SlimKeyPackage
in which the SlimLeafNode appears.

An OuterKeyPackageHash is valid only if the SlimLeafNode's
`leaf_node_source` is `key_package` and `outer_key_package_hash` equals the
hash of the enclosing SlimKeyPackage's `outer_key_package`.

The `app_data_dictionary` extension MUST contain exactly one
OuterKeyPackageHash component under component identifier TBD. A missing,
malformed, or duplicated OuterKeyPackageHash component makes the enclosing
SlimKeyPackage invalid.

## Creation and Processing

A sender constructs a SlimKeyPackage as follows:

1. Construct an OuterSlimKeyPackage with the desired version, cipher_suite,
   HPKEPublicKeyRef for the init key, and extensions.
2. Construct a SlimLeafNode with `leaf_node_source = key_package`. Add an
   `app_data_dictionary` extension containing an OuterKeyPackageHash whose
   value is the hash of the OuterSlimKeyPackage from step 1.
3. Sign the SlimLeafNode per {{!RFC9420}}.
4. Emit the SlimKeyPackage, optionally accompanied by a LargeObjectCarrier
   holding the referenced HPKEPublicKey and the large objects referenced by the
   SlimLeafNode.

A recipient processes a SlimKeyPackage like a KeyPackage with the following
exceptions:

- There is no outer signature to verify.
- The SlimLeafNode MUST contain an `app_data_dictionary` extension with a
  valid OuterKeyPackageHash component.
- All large-object `*Ref` values are resolved per {{large-object-carrier}}.

# SlimWelcome {#slim-welcome}

SlimWelcome makes two changes relative to the {{!RFC9420}} Welcome:

1. The per-recipient EncryptedGroupSecrets is replaced by a
   SlimEncryptedGroupSecrets ({{slim-egs}}), which permits the recipient to be
   identified either by SlimKeyPackageRef or by leaf index.
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
populate it with a plaintext WelcomeGroupInfo before delivering the SlimWelcome
to a recipient ({{welcome-group-info}}). In this mode, the GroupInfo used by the
sender to encrypt the SlimEncryptedGroupSecrets and the GroupInfo populated by
the DS MUST be byte-for-byte identical.

## SlimEncryptedGroupSecrets {#slim-egs}

SlimEncryptedGroupSecrets extends the {{!RFC9420}}
EncryptedGroupSecrets to allow either of two recipient identifiers:

~~~
enum {
  reserved(0),
  slim_key_package_ref(1),
  leaf_node_index(2),
  (255)
} RecipientIdentifierType;

struct {
  RecipientIdentifierType recipient_type;
  select (SlimEncryptedGroupSecrets.recipient_type) {
    case slim_key_package_ref:
      SlimKeyPackageRef new_member;
    case leaf_node_index:
      uint32 leaf_node_index;
  };
  HPKECiphertext encrypted_group_secrets;
} SlimEncryptedGroupSecrets;
~~~

A recipient locates the entry intended for it by matching either its own
SlimKeyPackageRef or its leaf in the group's ratchet tree via the leaf index.

The `leaf_node_index` recipient type MUST be used only when the
SlimEncryptedGroupSecrets is encrypted using a plaintext GroupInfo as context
and the delivered SlimWelcome carries `WelcomeGroupInfo.info_type = plaintext`.
Otherwise, the sender MUST use `slim_key_package_ref`.

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

The HPKE context used to encrypt and decrypt
`SlimEncryptedGroupSecrets.encrypted_group_secrets` depends on the GroupInfo
presentation. For the `encrypted` variant, the context is the
`encrypted_group_info` value, as in {{!RFC9420}}. For the `plaintext` variant,
and for SlimWelcomes sent with `group_info` absent, the context is the
TLS-encoded GroupInfo.

The outer `optional<WelcomeGroupInfo>` in the SlimWelcome additionally allows
the sender to omit the GroupInfo. This mode is intended for server-assisted
deployments where the sender and recipient can obtain the exact GroupInfo by
some channel other than the SlimWelcome.

A recipient that receives a SlimWelcome whose `group_info` field is
absent MUST consider the SlimWelcome invalid.

# SlimCommit {#slim-commit}

SlimCommit applies the split-delivery goal of
{{?I-D.mularczyk-mls-splitcommit}} to SlimMLS Commits: the DS can deliver to
each recipient only the HPKECiphertextRefs and HPKECiphertexts intended for that
recipient. It also applies the approach by
{{?I-D.kohbrok-mls-fewer-signatures}} to save one signature in case commits
contain a path, but do not rotate the sender's signature key.

A SlimMLS-aware sender MUST use a SlimCommit in place of an MLS Commit in a
group with the `slim_mls` extension.

A SlimCommit uses the `commit` ContentType, but is carried in the dedicated
`mls_slim_public_commit` and `mls_slim_private_commit` WireFormats
({{wire-formats}}). These wire formats allow the unsigned SlimUpdatePath to be
carried alongside the framed SlimCommit without being included in the transcript
hash, the membership tag, or the framing signature.

A SlimCommit carries the normal {{!RFC9420}} confirmation tag. When the
single-signature construction of {{single-sig-commits}} applies, the
authentication data contains the confirmation tag but omits the signature field,
as in {{?I-D.kohbrok-mls-fewer-signatures}}. Otherwise, the authentication data
contains both the confirmation tag and the framing signature.

~~~
struct {
  ProposalOrRef          proposals<V>;
  optional<SlimLeafNode> leaf_node;
} SlimCommit;
~~~

`leaf_node`, when present, is the committer's new SlimLeafNode.

## SlimUpdatePath

The path is conveyed separately from the framed SlimCommit:

~~~
struct {
  HPKEPublicKeyRef  encryption_key_ref;
  HPKECiphertextRef encrypted_path_secret_refs<V>;
} SlimUpdatePathNode;

struct {
  SlimUpdatePathNode nodes<V>;
} SlimUpdatePath;
~~~

Each SlimUpdatePathNode carries an HPKEPublicKeyRef for the new ParentNode
public key and a vector of HPKECiphertextRefs. In the sender-to-DS
SlimUpdatePath, the `encrypted_path_secret_refs` vector has the same order and
cardinality as the `encrypted_path_secret` vector in the corresponding
{{!RFC9420}} UpdatePathNode. In a DS-to-recipient SlimUpdatePath, the DS MAY
reduce each `encrypted_path_secret_refs` vector to the subset the recipient
needs. The reduced path MUST contain enough HPKECiphertextRefs for the recipient
to decrypt one path secret and derive the remaining path secrets it needs to
process the Commit. The corresponding HPKECiphertexts, and any HPKEPublicKeys
that are functionally needed, are resolved per {{large-object-carrier}}.

The SlimUpdatePath is not signed. Its HPKEPublicKeyRefs are authenticated by
the parent hash in the committer's SlimLeafNode, as in {{Section 7.9 of
!RFC9420}}, with HPKEPublicKeyRef replacing HPKEPublicKey in the parent-hash
computation. Its HPKECiphertextRefs are unauthenticated delivery objects: a
recipient validates them by decrypting the referenced HPKECiphertext, deriving
the path public keys, checking that the derived public keys hash to the
authenticated HPKEPublicKeyRefs, and verifying the Commit confirmation tag.

## SlimCommit Framing {#slim-commit-framing}

SlimCommit uses dedicated public and private message structures. They are the
same as {{!RFC9420}} PublicMessage and PrivateMessage, except that the commit
content is a SlimCommit, the authentication data is a
SlimCommitFramedContentAuthData, and the optional SlimUpdatePath is carried
outside the authenticated content.

~~~
struct {
  opaque group_id<V>;
  uint64 epoch;
  Sender sender;
  opaque authenticated_data<V>;

  ContentType content_type;
  select (SlimCommitFramedContent.content_type) {
    case commit:
      SlimCommit commit;
  };
} SlimCommitFramedContent;

struct {
  /*
    SignWithLabel(., "FramedContentTBS",
      SlimCommitFramedContentTBS)
  */
  optional<opaque<V>> signature;

  /*
    MAC(confirmation_key,
      GroupContext.confirmed_transcript_hash)
  */
  MAC confirmation_tag;
} SlimCommitFramedContentAuthData;

struct {
  ProtocolVersion         version = mls10;
  WireFormat              wire_format;
  SlimCommitFramedContent content;
  select (SlimCommitFramedContentTBS.content.sender.sender_type) {
    case member:
    case new_member_commit:
      GroupContext context;
    case external:
    case new_member_proposal:
      struct{};
  };
} SlimCommitFramedContentTBS;

struct {
  WireFormat                         wire_format;
  SlimCommitFramedContent            content;
  SlimCommitFramedContentAuthData    auth;
} SlimCommitAuthenticatedContent;

struct {
  SlimCommitFramedContent         content;
  SlimCommitFramedContentAuthData auth;
  select (SlimPublicCommitMessage.content.sender.sender_type) {
    case member:
      MAC membership_tag;
    case external:
    case new_member_commit:
    case new_member_proposal:
      struct{};
  };
  optional<SlimUpdatePath> path;
} SlimPublicCommitMessage;

struct {
  SlimCommit                      commit;
  SlimCommitFramedContentAuthData auth;
  opaque                          padding[length_of_padding];
} SlimPrivateCommitMessageContent;

struct {
  opaque group_id<V>;
  uint64 epoch;
  ContentType content_type;
  opaque authenticated_data<V>;
  opaque encrypted_sender_data<V>;
  opaque ciphertext<V>;
  optional<SlimUpdatePath> path;
} SlimPrivateCommitMessage;
~~~

The `content_type` field in SlimCommitFramedContent and
SlimPrivateCommitMessage MUST be `commit`.

For SlimPrivateCommitMessage, the `ciphertext` field encrypts a
SlimPrivateCommitMessageContent. The sender data encryption, content encryption,
padding, and decryption rules are otherwise the same as for PrivateMessage in
{{!RFC9420}}.

After decrypting a SlimPrivateCommitMessage, the recipient reconstructs the
SlimCommitFramedContent from the outer `group_id`, `epoch`, `content_type`, and
`authenticated_data` fields, the decrypted sender, and the decrypted SlimCommit.
This reconstructed SlimCommitFramedContent is used for signature verification,
OuterUpdateHash verification, transcript hash computation, and confirmation tag
verification.

The optional `signature` field in SlimCommitFramedContentAuthData MUST be
absent if and only if the single-signature construction of
{{single-sig-commits}} applies. When present, the signature is computed and
verified as in {{!RFC9420}}, except that the to-be-signed content is
SlimCommitFramedContentTBS and the WireFormat is either `mls_slim_public_commit`
or `mls_slim_private_commit`.

For SlimPublicCommitMessage, the membership tag is computed over the following
structure:

~~~
struct {
  SlimCommitFramedContentTBS      content_tbs;
  SlimCommitFramedContentAuthData auth;
} SlimCommitAuthenticatedContentTBM;
~~~

For transcript hash computation, the confirmed transcript hash input is:

~~~
struct {
  WireFormat              wire_format;
  SlimCommitFramedContent content;
} SlimCommitConfirmedTranscriptHashInput;
~~~

The SlimUpdatePath is not part of SlimCommitFramedContent,
SlimCommitAuthenticatedContentTBM, or SlimCommitConfirmedTranscriptHashInput.
It is therefore not authenticated by the membership tag, the framing signature,
or the transcript hash.

## SlimCommitMessage

SlimCommitMessage is the generic term for the two concrete wire presentations,
SlimPublicCommitMessage and SlimPrivateCommitMessage. Both presentations are
used for sender-to-DS transport and for DS-to-recipient delivery; the difference
between the two is the cardinality of the HPKECiphertextRef vectors in `path`.

## Single Signature Construction {#single-sig-commits}

When a SlimCommit is sent by a member, contains a SlimLeafNode, and the sender's
signature key is unchanged, the construction of
{{?I-D.kohbrok-mls-fewer-signatures}} applies: the framing signature is omitted,
and authenticity is provided by the SlimLeafNode's own signature in combination
with an OuterUpdateHash component placed in the SlimLeafNode's
`app_data_dictionary` extension. The confirmation tag is still present and
processed as in {{!RFC9420}}.

The OuterUpdateHash binds the framed SlimCommit (excluding the SlimLeafNode
itself, to avoid a circular dependency) and the GroupContext to the
SlimLeafNode:

~~~
struct {
  opaque outer_update_hash<V>;
} OuterUpdateHash;

struct {
  opaque       group_id<V>;
  uint64       epoch;
  Sender       sender;
  opaque       authenticated_data<V>;
  ContentType  content_type;
  select (OuterFramedContent.content_type) {
    case commit:
      ProposalOrRef proposals<V>;
  };
} OuterFramedContent;

struct {
  ProtocolVersion    version = mls10;
  WireFormat         wire_format;
  OuterFramedContent content;
  GroupContext       context;
} SlimFramedContentTBH;
~~~

`outer_update_hash` is the hash, under the group's ciphersuite hash function,
of the TLS-encoded SlimFramedContentTBH. Fields of OuterFramedContent are
populated from the SlimCommit being framed; the SlimLeafNode is omitted to
prevent the circular dependency that would arise from including the very
component being computed.

The `app_data_dictionary` extension MUST contain exactly one OuterUpdateHash
component under component identifier TBD. A missing, malformed, or duplicated
OuterUpdateHash component makes the single-signature construction invalid.

The OuterUpdateHash authenticates the non-path commit contents that the omitted
framing signature would otherwise cover. The path's HPKEPublicKeyRefs are
authenticated separately by parent hash validation. The path's
HPKECiphertextRefs are not authenticated by the signature and do not contribute
to the group state; tampering with them can only cause decryption, derived-key,
or confirmation-tag validation to fail.

When the construction applies, the SignaturePublicKeyRef in the SlimLeafNode
MUST equal the sender's current SignaturePublicKeyRef. A sender that wishes
to change its signature key MUST instead emit a SlimCommit whose authentication
data carries a framing signature, so that the new key is bound by a signature
under the old one.

A SlimCommit without a SlimLeafNode (e.g., a commit containing only Add or
Remove proposals) does not use this construction; its authentication data
carries a framing signature.

A SlimCommit whose sender type is not `member` does not use this construction;
its authentication data carries a framing signature.

## Sender, DS, and Recipient Behavior

A committer constructs a SlimCommitMessage as follows:

1. Perform the steps of an {{!RFC9420}} commit, deriving the path's
   HPKEPublicKeys, HPKECiphertexts, parent hashes, and the new epoch's key
   schedule. Parent hashes are computed over the slim parent-hash inputs, with
   HPKEPublicKeyRef replacing HPKEPublicKey.
2. Build a SlimCommit containing the committed proposals and, if the commit
   contains a path, the committer's new SlimLeafNode. The SlimLeafNode's
   parent hash MUST authenticate the HPKEPublicKeyRefs in the SlimUpdatePath.
3. Compute the confirmation tag for the new epoch as in {{!RFC9420}}.
4. If the single-signature construction applies, include a valid OuterUpdateHash
   in the SlimLeafNode and leave the optional signature field absent. Otherwise,
   include the normal framing signature in the optional signature field.
5. Build a SlimUpdatePath whose SlimUpdatePathNodes carry the HPKEPublicKeyRefs
   and HPKECiphertextRefs of the path, and emit a SlimPublicCommitMessage or
   SlimPrivateCommitMessage, optionally accompanied by a LargeObjectCarrier
   holding the corresponding HPKEPublicKeys and HPKECiphertexts.

The DS, knowing the ratchet tree before and after the commit, produces a
per-recipient SlimCommitMessage by reducing each SlimUpdatePathNode's
HPKECiphertextRef vector to the subset needed by that recipient. The DS MUST
retain the HPKEPublicKeyRef in every SlimUpdatePathNode, and MUST retain enough
HPKECiphertextRefs for the recipient to decrypt one path secret and derive the
remaining path secrets it needs to process the Commit. If a LargeObjectCarrier
is present, the DS reduces it accordingly, retaining only any HPKEPublicKeys the
recipient must receive and the HPKECiphertexts corresponding to the retained
HPKECiphertextRefs. If the commit removes the recipient, `path` is omitted.

A recipient processes a SlimCommitMessage by:

1. Resolving the HPKECiphertextRefs required for the recipient, and any
   HPKEPublicKeyRefs that are functionally needed, per {{large-object-carrier}}.
2. If SlimCommitFramedContentAuthData contains a signature, verifying it per
   {{!RFC9420}} using SlimCommitFramedContentTBS. Otherwise, verifying the
   SlimLeafNode signature and OuterUpdateHash per {{single-sig-commits}}.
3. Decrypting the resolved HPKECiphertext, deriving the path public keys, and
   verifying that the derived public keys hash to the authenticated
   HPKEPublicKeyRefs.
4. Applying the path update and verifying parent hashes over the slim encodings
   per {{Section 7.9.2 of !RFC9420}}.
5. Processing the commit per {{Section 12.4 of !RFC9420}}, deriving the new
   epoch, and verifying the confirmation tag. If confirmation tag validation
   fails, the recipient MUST reject the commit.

The input to the confirmed transcript hash is
SlimCommitConfirmedTranscriptHashInput. The interim transcript hash is computed
from the confirmed transcript hash and the confirmation tag as in {{!RFC9420}}.

DSs that do not maintain the ratchet tree cannot perform the per-recipient
reduction described above. Strategies for such deployments are out of scope, as
in {{?I-D.mularczyk-mls-splitcommit}}.

# Optimizing Payload Sizes

The separation of large objects and their references in structs that are sent
over the wire or stored locally allows a few performance optimizations. They are
up to the application to implement.

## Storing Partial Trees

SlimMLS clients need the slim public tree for MLS tree computations, but they
do not need to fetch every large object referenced by that tree. Tree hashes,
parent hashes, and GroupInfo validation are computed over SlimLeafNode and
SlimParentNode encodings, so the references to public keys and credentials are
the values committed to by those computations. A client can therefore defer
fetching large objects that are not functionally needed, such as HPKE public
keys outside the client's copath. This is especially relevant when joining a
group, where the DS can selectively include the public keys and credentials the
joiner needs immediately.

## Omitting Cached Large Objects

If the DS keeps track of the group's public state, clients that send a commit
with an update path only need to proactively provide the signature public key and
credential if either of them change as part of the commit.

## Cross-group Credential Caching

If clients use the same credential across multiple groups, other clients can
cache them and pull new credentials selectively when they encounter credential
references they can't resolve. Whether this is a performance increase depends on
the context of the application.

The DS can similarly deduplicate stored credentials.

## Delayed Fetching of Large Objects

Clients that have been offline for some time can fetch and process slim messages
first. It can wait to fetch large objects that are not relevant for processing
(such as HPKE public keys) until it has arrived at the current group state. The
client thus avoids downloading stale, intermediate large objects.

# Wire Formats {#wire-formats}

SlimMLS introduces new WireFormat values only where a recipient cannot know
from context that SlimMLS framing is in use, or where SlimMLS changes the
message framing. This applies to SlimKeyPackages, SlimWelcomes, and SlimCommit
messages.

MLSMessage is correspondingly extended with the following new cases:

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
    case mls_slim_public_commit:
      SlimPublicCommitMessage   slim_public_commit;
    case mls_slim_private_commit:
      SlimPrivateCommitMessage  slim_private_commit;
  };
} MLSMessage;
~~~

A SlimMLS-aware sender MAY use `mls_slim_key_package` for any SlimKeyPackage
publication and MUST use `mls_slim_welcome` for any SlimWelcome delivery in
the context of a group with the `slim_mls` extension. A SlimMLS-aware sender
MUST use `mls_slim_public_commit` or `mls_slim_private_commit` for any
SlimCommit delivery in the context of a group with the `slim_mls` extension.

# The slim_mls Extension {#slim-mls-extension}

SlimMLS is signaled by a GroupContext extension named `slim_mls`. Presence
of this extension in the GroupContext means that all wire formats within
the group use SlimMLS replacements.

# The slim_ratchet_tree Extension {#slim-ratchet-tree-extension}

The {{!RFC9420}} `ratchet_tree` GroupInfo extension carries LeafNode and
ParentNode objects. SlimMLS defines a `slim_ratchet_tree` GroupInfo extension
that conveys the same tree using SlimLeafNode and SlimParentNode objects:

~~~
struct {
    NodeType node_type;
    select (SlimNode.node_type) {
        case leaf:   SlimLeafNode leaf_node;
        case parent: SlimParentNode parent_node;
    };
} SlimNode;

optional<SlimNode> slim_ratchet_tree<V>;
~~~

The ordering, truncation, and validation rules are the same as for the
`ratchet_tree` extension in {{Section 12.4.3.3 of !RFC9420}}, except that tree
hash and parent hash computations use the slim node encodings. The large
objects referenced by the slim nodes are resolved per
{{large-object-carrier}}.

In a SlimMLS group, the {{!RFC9420}} `ratchet_tree` extension MUST NOT be used.
A sender that would include `ratchet_tree` MUST instead include the
`slim_ratchet_tree` extension.

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
resolved per {{large-object-carrier}}, as for any other HPKEPublicKeyRef.


# Security Considerations

Outside the SlimCommit split path described below, the signing and
transcript-hashing rules of {{!RFC9420}} are preserved by SlimMLS: every struct
that was authenticated under {{!RFC9420}} remains authenticated, with large
objects bound through the collision-resistant hash references defined in
{{ref-types}}. The strength of the binding is therefore at most the collision
resistance of the ciphersuite hash.

SlimCommit ({{slim-commit}}) changes the exact authentication surface of
Commits with paths. The path's HPKEPublicKeyRefs are not covered directly by the
framing signature or OuterUpdateHash, but are authenticated by the parent hash
chain rooted in the signed SlimLeafNode. The path's HPKECiphertextRefs are not
authenticated by the signature and are treated as delivery objects. Tampering
with an HPKECiphertextRef or the referenced HPKECiphertext can only cause the
recipient to fail reference resolution, decryption, derived-public-key matching,
parent-hash validation, or confirmation-tag validation.

The LargeObjectCarrier ({{large-object-carrier}}) is unauthenticated by design.
A Delivery Service or network attacker that withholds, modifies, or substitutes
carrier entries can only cause a recipient to fail to resolve a reference, which
is functionally equivalent to dropping the message, which the DS can already do
under {{!RFC9420}}. A recipient MUST verify that any object it consumes from the
carrier hashes (under the appropriate label and the ciphersuite hash) to the
corresponding large-object `*Ref` in the slim structure or associated
unauthenticated structure before using that object for any cryptographic
operation.

Because the carrier is unauthenticated, an attacker can also include
unsolicited or malformed objects in it. Recipients MUST NOT treat the
carrier as authoritative metadata and MUST ignore objects whose hash does
not match any reference the recipient needs to process the slim structure or an
associated unauthenticated structure.

A client that caches resolved large objects across groups MUST index its
cache by the tuple (reference type, ciphersuite hash function, reference value).
The same underlying object yields different reference values under different
hash functions, and a cached object MUST NOT be treated as authoritative across
ciphersuites whose hash functions differ.

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
| TBD   | slim_ratchet_tree | GI         | Y           | RFC XXXX  |
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
| TBD   | mls_slim_public_commit | Y          | RFC XXXX  |
| TBD   | mls_slim_private_commit | Y         | RFC XXXX  |


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
