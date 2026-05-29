#!/usr/bin/env python3
"""Compute rough MLS and SlimMLS message-size matrices.

The model is intentionally explicit rather than clever.  It computes the
TLS-encoded sizes of a Welcome and a public Commit with an update path under a
small set of assumptions that are documented in the generated markdown.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import itertools
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class CipherSuite:
    name: str
    hash_len: int
    hpke_public_key_len: int
    hpke_kem_output_len: int
    signature_public_key_len: int
    signature_len: int
    aead_tag_len: int = 16
    note: str = ""


@dataclass(frozen=True)
class MessageSizes:
    welcome_message: int
    welcome_carrier: int
    commit_sender_message: int
    commit_sender_carrier: int
    commit_member_message: int
    commit_member_carrier: int
    path_nodes: int

    @property
    def welcome_total(self) -> int:
        return self.welcome_message + self.welcome_carrier

    @property
    def commit_sender_total(self) -> int:
        return self.commit_sender_message + self.commit_sender_carrier

    @property
    def commit_member_total(self) -> int:
        return self.commit_member_message + self.commit_member_carrier

    def commit_aggregate(self, group_size: int) -> int:
        recipients = max(group_size - 1, 0)
        return self.commit_sender_total + recipients * self.commit_member_total


BASIC_DELIVERY = "basic"
UPDATE_DELIVERY = "update"
DELIVERY_CAPABILITIES = {BASIC_DELIVERY, UPDATE_DELIVERY}
SLIM_COMMIT_SINGLE_SIGNATURE = "single-signature"
SLIM_COMMIT_FRAMING_SIGNATURE = "framing-signature"
SLIM_COMMIT_AUTH_MODES = {
    SLIM_COMMIT_SINGLE_SIGNATURE,
    SLIM_COMMIT_FRAMING_SIGNATURE,
}


PROTOCOL_VERSION_LEN = 2
CIPHERSUITE_LEN = 2
WIRE_FORMAT_LEN = 2
MLS_MESSAGE_HEADER_LEN = PROTOCOL_VERSION_LEN + WIRE_FORMAT_LEN
EXTENSION_TYPE_LEN = 2
CREDENTIAL_TYPE_LEN = 2
APP_DATA_COMPONENT_ID_LEN = 2
GROUP_EPOCH_LEN = 8
LEAF_INDEX_LEN = 4
TREE_SIZE_LEN = 4
SENDER_TYPE_LEN = 1
CONTENT_TYPE_LEN = 1
NODE_TYPE_LEN = 1
LEAF_NODE_SOURCE_LEN = 1
ENUM_LEN = 1
GROUP_INFO_SIGNER_LEN = 4
LIFETIME_LEN = 16  # uint64 not_before + uint64 not_after.

SHA256_LEN = 32
SHA384_LEN = 48
SHA512_LEN = 64

X25519_PUBLIC_KEY_LEN = 32
X25519_KEM_OUTPUT_LEN = 32
X448_PUBLIC_KEY_LEN = 56
X448_KEM_OUTPUT_LEN = 56

ED25519_PUBLIC_KEY_LEN = 32
ED25519_SIGNATURE_LEN = 64
ED448_PUBLIC_KEY_LEN = 57
ED448_SIGNATURE_LEN = 114

P256_PUBLIC_KEY_LEN = 65  # TLS UncompressedPointRepresentation.
P384_PUBLIC_KEY_LEN = 97
# ECDSA signatures are DER encoded and variable length. Use the maximum common
# DER size for each curve so the estimates are conservative.
P256_ECDSA_SIGNATURE_LEN = 72
P384_ECDSA_SIGNATURE_LEN = 104

MLDSA65_PUBLIC_KEY_LEN = 1952
MLDSA65_SIGNATURE_LEN = 3309
MLDSA87_PUBLIC_KEY_LEN = 2592
MLDSA87_SIGNATURE_LEN = 4627

MLKEM768_PUBLIC_KEY_LEN = 1184
MLKEM768_KEM_OUTPUT_LEN = 1088
MLKEM1024_PUBLIC_KEY_LEN = 1568
MLKEM1024_KEM_OUTPUT_LEN = 1568

MLKEM768_X25519_PUBLIC_KEY_LEN = 1216
MLKEM768_X25519_KEM_OUTPUT_LEN = 1120
MLKEM768_P256_PUBLIC_KEY_LEN = 1249
MLKEM768_P256_KEM_OUTPUT_LEN = 1153
MLKEM1024_P384_PUBLIC_KEY_LEN = 1665
MLKEM1024_P384_KEM_OUTPUT_LEN = 1665

SUPPORTED_CIPHERSUITES: dict[str, CipherSuite] = {}


def add_suite(*aliases: str, suite: CipherSuite) -> None:
    for alias in aliases:
        SUPPORTED_CIPHERSUITES[alias.lower()] = suite


add_suite(
    "mti",
    "x25519-ed25519",
    "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    suite=CipherSuite(
        name="MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        hash_len=SHA256_LEN,
        hpke_public_key_len=X25519_PUBLIC_KEY_LEN,
        hpke_kem_output_len=X25519_KEM_OUTPUT_LEN,
        signature_public_key_len=ED25519_PUBLIC_KEY_LEN,
        signature_len=ED25519_SIGNATURE_LEN,
        note="MLS 1.0 MTI ciphersuite.",
    ),
)

add_suite(
    "x448-ed448",
    "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
    suite=CipherSuite(
        name="MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
        hash_len=SHA512_LEN,
        hpke_public_key_len=X448_PUBLIC_KEY_LEN,
        hpke_kem_output_len=X448_KEM_OUTPUT_LEN,
        signature_public_key_len=ED448_PUBLIC_KEY_LEN,
        signature_len=ED448_SIGNATURE_LEN,
        note="MLS 1.0 X448/Ed448 ciphersuite.",
    ),
)

add_suite(
    "pq-tbd1",
    "mlkem768x25519-ed25519-sha384",
    "MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519",
    suite=CipherSuite(
        name="MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519",
        hash_len=SHA384_LEN,
        hpke_public_key_len=MLKEM768_X25519_PUBLIC_KEY_LEN,
        hpke_kem_output_len=MLKEM768_X25519_KEM_OUTPUT_LEN,
        signature_public_key_len=ED25519_PUBLIC_KEY_LEN,
        signature_len=ED25519_SIGNATURE_LEN,
        note="draft-ietf-mls-pq-ciphersuites-01 TBD1.",
    ),
)

add_suite(
    "pq-tbd2",
    "mlkem768p256-p256",
    "MLS_128_MLKEM768P256_AES256GCM_SHA384_P256",
    suite=CipherSuite(
        name="MLS_128_MLKEM768P256_AES256GCM_SHA384_P256",
        hash_len=SHA384_LEN,
        hpke_public_key_len=MLKEM768_P256_PUBLIC_KEY_LEN,
        hpke_kem_output_len=MLKEM768_P256_KEM_OUTPUT_LEN,
        signature_public_key_len=P256_PUBLIC_KEY_LEN,
        signature_len=P256_ECDSA_SIGNATURE_LEN,
        note="draft-ietf-mls-pq-ciphersuites-01 TBD2.",
    ),
)

add_suite(
    "pq-tbd3",
    "mlkem1024p384-p384",
    "MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384",
    suite=CipherSuite(
        name="MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384",
        hash_len=SHA384_LEN,
        hpke_public_key_len=MLKEM1024_P384_PUBLIC_KEY_LEN,
        hpke_kem_output_len=MLKEM1024_P384_KEM_OUTPUT_LEN,
        signature_public_key_len=P384_PUBLIC_KEY_LEN,
        signature_len=P384_ECDSA_SIGNATURE_LEN,
        note="draft-ietf-mls-pq-ciphersuites-01 TBD3.",
    ),
)

add_suite(
    "pq-tbd4",
    "mlkem768-p256",
    "MLS_128_MLKEM768_AES256GCM_SHA384_P256",
    suite=CipherSuite(
        name="MLS_128_MLKEM768_AES256GCM_SHA384_P256",
        hash_len=SHA384_LEN,
        hpke_public_key_len=MLKEM768_PUBLIC_KEY_LEN,
        hpke_kem_output_len=MLKEM768_KEM_OUTPUT_LEN,
        signature_public_key_len=P256_PUBLIC_KEY_LEN,
        signature_len=P256_ECDSA_SIGNATURE_LEN,
        note="draft-ietf-mls-pq-ciphersuites-01 TBD4.",
    ),
)

add_suite(
    "pq-tbd5",
    "mlkem1024-p384",
    "MLS_192_MLKEM1024_AES256GCM_SHA384_P384",
    suite=CipherSuite(
        name="MLS_192_MLKEM1024_AES256GCM_SHA384_P384",
        hash_len=SHA384_LEN,
        hpke_public_key_len=MLKEM1024_PUBLIC_KEY_LEN,
        hpke_kem_output_len=MLKEM1024_KEM_OUTPUT_LEN,
        signature_public_key_len=P384_PUBLIC_KEY_LEN,
        signature_len=P384_ECDSA_SIGNATURE_LEN,
        note="draft-ietf-mls-pq-ciphersuites-01 TBD5.",
    ),
)

add_suite(
    "pq-tbd6",
    "mlkem768-mldsa65",
    "MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65",
    suite=CipherSuite(
        name="MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65",
        hash_len=SHA384_LEN,
        hpke_public_key_len=MLKEM768_PUBLIC_KEY_LEN,
        hpke_kem_output_len=MLKEM768_KEM_OUTPUT_LEN,
        signature_public_key_len=MLDSA65_PUBLIC_KEY_LEN,
        signature_len=MLDSA65_SIGNATURE_LEN,
        note="draft-ietf-mls-pq-ciphersuites-01 TBD6.",
    ),
)

add_suite(
    "pq-tbd7",
    "mlkem1024-mldsa87-sha512",
    "MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87",
    suite=CipherSuite(
        name="MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87",
        hash_len=SHA384_LEN,
        hpke_public_key_len=MLKEM1024_PUBLIC_KEY_LEN,
        hpke_kem_output_len=MLKEM1024_KEM_OUTPUT_LEN,
        signature_public_key_len=MLDSA87_PUBLIC_KEY_LEN,
        signature_len=MLDSA87_SIGNATURE_LEN,
        note=(
            "draft-ietf-mls-pq-ciphersuites-01 TBD7; Table 2 maps this to "
            "SHA384 despite the candidate name containing SHA512."
        ),
    ),
)

add_suite(
    "mlkem768x25519-ed25519",
    "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519",
    suite=CipherSuite(
        name="MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519",
        hash_len=SHA256_LEN,
        hpke_public_key_len=MLKEM768_X25519_PUBLIC_KEY_LEN,
        hpke_kem_output_len=MLKEM768_X25519_KEM_OUTPUT_LEN,
        signature_public_key_len=ED25519_PUBLIC_KEY_LEN,
        signature_len=ED25519_SIGNATURE_LEN,
        note="Hybrid ML-KEM768+X25519 KEM with Ed25519 signatures.",
    ),
)

add_suite(
    "mlkem1024-mldsa87",
    "MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87",
    suite=CipherSuite(
        name="MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87",
        hash_len=SHA384_LEN,
        hpke_public_key_len=MLKEM1024_PUBLIC_KEY_LEN,
        hpke_kem_output_len=MLKEM1024_KEM_OUTPUT_LEN,
        signature_public_key_len=MLDSA87_PUBLIC_KEY_LEN,
        signature_len=MLDSA87_SIGNATURE_LEN,
        note="ML-KEM1024 KEM with ML-DSA87 signatures.",
    ),
)


def varint_len(value: int) -> int:
    """Return the RFC 9420/TLS Presentation Language vector length width."""
    if value < 0:
        raise ValueError("negative lengths are invalid")
    if value <= 63:
        return 1
    if value <= 16_383:
        return 2
    if value <= 1_073_741_823:
        return 4
    raise ValueError(f"length too large for MLS vector encoding: {value}")


def opaque_len(payload_len: int) -> int:
    return varint_len(payload_len) + payload_len


def vector_len(items: Iterable[int]) -> int:
    payload_len = sum(items)
    return varint_len(payload_len) + payload_len


def empty_vector_len() -> int:
    return 1


def optional_len(payload_len: int | None) -> int:
    return 1 if payload_len is None else 1 + payload_len


def ref_len(suite: CipherSuite) -> int:
    return opaque_len(suite.hash_len)


def mac_len(suite: CipherSuite) -> int:
    return opaque_len(suite.hash_len)


def hpke_public_key_len(suite: CipherSuite) -> int:
    return opaque_len(suite.hpke_public_key_len)


def signature_public_key_len(suite: CipherSuite) -> int:
    return opaque_len(suite.signature_public_key_len)


def signature_len(suite: CipherSuite) -> int:
    return opaque_len(suite.signature_len)


def hpke_ciphertext_len(suite: CipherSuite, plaintext_len: int) -> int:
    return (
        opaque_len(suite.hpke_kem_output_len)
        + opaque_len(plaintext_len + suite.aead_tag_len)
    )


def capabilities_len(extension_type_count: int = 0) -> int:
    # Each advertised ProtocolVersion, CipherSuite, ExtensionType, ProposalType,
    # and CredentialType is a uint16 value.
    versions = vector_len([PROTOCOL_VERSION_LEN])
    cipher_suites = vector_len([CIPHERSUITE_LEN])
    extensions = (
        vector_len([EXTENSION_TYPE_LEN] * extension_type_count)
        if extension_type_count > 0
        else empty_vector_len()
    )
    proposals = empty_vector_len()
    credentials = vector_len([CREDENTIAL_TYPE_LEN])
    return versions + cipher_suites + extensions + proposals + credentials


def leaf_hash_extension_vector_len(suite: CipherSuite) -> int:
    """Model one app_data_dictionary component containing one hash value.

    SlimMLS currently leaves the concrete app_data_dictionary syntax out of the
    draft.  This uses a minimal component encoding:

      uint16 component_id;
      opaque component_data<V>;  // an Outer*Hash struct

    where the Outer*Hash struct itself contains one opaque hash value.
    """
    outer_hash_struct = ref_len(suite)
    component = APP_DATA_COMPONENT_ID_LEN + opaque_len(outer_hash_struct)
    app_data_dictionary = vector_len([component])
    extension = EXTENSION_TYPE_LEN + opaque_len(app_data_dictionary)
    return vector_len([extension])


def source_specific_len(suite: CipherSuite, source: str) -> int:
    if source == "key_package":
        return LIFETIME_LEN
    if source == "commit":
        return ref_len(suite)  # parent_hash
    if source == "update":
        return 0
    raise ValueError(f"unknown LeafNode source: {source}")


def regular_leaf_node_len(
    suite: CipherSuite, credential_size: int, source: str
) -> int:
    # LeafNode fields in RFC order: encryption key, signature key, credential,
    # capabilities, leaf_node_source, source-specific fields, extensions,
    # signature.
    leaf_node_source = LEAF_NODE_SOURCE_LEN
    extensions = empty_vector_len()
    return (
        hpke_public_key_len(suite)
        + signature_public_key_len(suite)
        + credential_size
        + capabilities_len()
        + leaf_node_source
        + source_specific_len(suite, source)
        + extensions
        + signature_len(suite)
    )


def slim_key_package_merkle_proof_len(
    suite: CipherSuite, key_package_batch_size: int
) -> int:
    proof_nodes = math.ceil(math.log2(key_package_batch_size))
    return (
        LEAF_INDEX_LEN
        + TREE_SIZE_LEN
        + vector_len([ref_len(suite)] * proof_nodes)
    )


def slim_leaf_node_len(
    suite: CipherSuite,
    source: str,
    has_outer_hash: bool,
    key_package_batch_size: int,
) -> int:
    # SlimLeafNode replaces the LeafNode's three large objects with references:
    # encryption_key_ref, signature_key_ref, and credential_ref.
    large_object_refs = ref_len(suite) + ref_len(suite) + ref_len(suite)
    leaf_node_source = LEAF_NODE_SOURCE_LEN
    # SlimMLS leaves need to advertise the slim_mls GroupContext extension.
    # Leaves with app_data_dictionary components additionally advertise that
    # LeafNode extension.
    extension_type_count = 1 + int(has_outer_hash)
    extensions = (
        leaf_hash_extension_vector_len(suite)
        if has_outer_hash
        else empty_vector_len()
    )
    proof = (
        slim_key_package_merkle_proof_len(suite, key_package_batch_size)
        if source == "key_package"
        else 0
    )
    return (
        large_object_refs
        + capabilities_len(extension_type_count)
        + leaf_node_source
        + source_specific_len(suite, source)
        + extensions
        + ref_len(suite)  # SignatureRef
        + proof
    )


def regular_parent_node_len(suite: CipherSuite, is_root: bool = False) -> int:
    # ParentNode = HPKEPublicKey encryption_key, parent_hash, unmerged_leaves.
    parent_hash = opaque_len(0) if is_root else ref_len(suite)
    return hpke_public_key_len(suite) + parent_hash + empty_vector_len()


def slim_parent_node_len(suite: CipherSuite, is_root: bool = False) -> int:
    # SlimParentNode = HPKEPublicKeyRef encryption_key_ref, parent_hash,
    # unmerged_leaves.
    parent_hash = opaque_len(0) if is_root else ref_len(suite)
    return ref_len(suite) + parent_hash + empty_vector_len()


def tree_node_count(group_size: int) -> int:
    # A binary ratchet tree with n leaves has n - 1 parent nodes.
    return max(2 * group_size - 1, 0)


def path_node_count(group_size: int) -> int:
    if group_size <= 1:
        return 0
    return math.ceil(math.log2(group_size))


def ratchet_tree_extension_data_len(
    suite: CipherSuite,
    protocol: str,
    tree_mode: str,
    group_size: int,
    credential_size: int,
    key_package_batch_size: int,
) -> int:
    if group_size < 1:
        raise ValueError("group size must be at least 1")

    if tree_mode == "sparse":
        return vector_len([optional_len(None)] * tree_node_count(group_size))

    if protocol == "regular":
        # Each ratchet_tree element is optional<Node>. A present Node adds a
        # one-byte NodeType before the LeafNode or ParentNode body.
        committer_leaf = optional_len(
            NODE_TYPE_LEN + regular_leaf_node_len(suite, credential_size, "commit")
        )
        member_leaf = optional_len(
            NODE_TYPE_LEN
            + regular_leaf_node_len(suite, credential_size, "key_package")
        )
        parent = optional_len(NODE_TYPE_LEN + regular_parent_node_len(suite))
        root_parent = optional_len(
            NODE_TYPE_LEN + regular_parent_node_len(suite, is_root=True)
        )
    elif protocol == "slim":
        # Same optional<Node> and NodeType wrapper, but with SlimNode contents.
        committer_leaf = optional_len(
            NODE_TYPE_LEN
            + slim_leaf_node_len(
                suite,
                "commit",
                has_outer_hash=True,
                key_package_batch_size=key_package_batch_size,
            )
        )
        member_leaf = optional_len(
            NODE_TYPE_LEN
            + slim_leaf_node_len(
                suite,
                "key_package",
                has_outer_hash=True,
                key_package_batch_size=key_package_batch_size,
            )
        )
        parent = optional_len(NODE_TYPE_LEN + slim_parent_node_len(suite))
        root_parent = optional_len(
            NODE_TYPE_LEN + slim_parent_node_len(suite, is_root=True)
        )
    else:
        raise ValueError(f"unknown protocol: {protocol}")

    nodes = [committer_leaf]
    nodes.extend([member_leaf] * (group_size - 1))
    if group_size > 1:
        nodes.append(root_parent)
        nodes.extend([parent] * (group_size - 2))
    return vector_len(nodes)


def extension_vector_with_single_extension(extension_data_len: int) -> int:
    extension = EXTENSION_TYPE_LEN + opaque_len(extension_data_len)
    return vector_len([extension])


def group_context_len(suite: CipherSuite, protocol: str, group_id_size: int) -> int:
    extensions = empty_vector_len()
    if protocol == "slim":
        # The slim_mls GroupContext extension has an ExtensionType and empty data.
        slim_mls_extension = EXTENSION_TYPE_LEN + opaque_len(0)
        extensions = vector_len([slim_mls_extension])

    return (
        PROTOCOL_VERSION_LEN
        + CIPHERSUITE_LEN
        + opaque_len(group_id_size)
        + GROUP_EPOCH_LEN
        + ref_len(suite)  # tree_hash
        + ref_len(suite)  # confirmed_transcript_hash
        + extensions
    )


def group_info_len(
    suite: CipherSuite,
    protocol: str,
    tree_mode: str,
    group_size: int,
    credential_size: int,
    group_id_size: int,
    key_package_batch_size: int,
) -> int:
    tree_extension_data = ratchet_tree_extension_data_len(
        suite,
        protocol,
        tree_mode,
        group_size,
        credential_size,
        key_package_batch_size,
    )
    signature = (
        ENUM_LEN + ref_len(suite)
        if protocol == "slim"
        else signature_len(suite)
    )
    return (
        group_context_len(suite, protocol, group_id_size)
        + extension_vector_with_single_extension(tree_extension_data)
        + mac_len(suite)
        + GROUP_INFO_SIGNER_LEN
        + signature
    )


def group_secrets_plaintext_len(suite: CipherSuite) -> int:
    joiner_secret = opaque_len(suite.hash_len)
    # Welcome GroupSecrets contains an optional path_secret and a PSK vector.
    path_secret = optional_len(opaque_len(suite.hash_len))
    psks = empty_vector_len()
    return joiner_secret + path_secret + psks


def regular_welcome_message_len(
    suite: CipherSuite,
    tree_mode: str,
    group_size: int,
    credential_size: int,
    group_id_size: int,
    key_package_batch_size: int,
) -> int:
    encrypted_group_secrets = (
        ref_len(suite)  # KeyPackageRef new_member
        + hpke_ciphertext_len(suite, group_secrets_plaintext_len(suite))
    )
    secrets = vector_len([encrypted_group_secrets])
    group_info = group_info_len(
        suite,
        "regular",
        tree_mode,
        group_size,
        credential_size,
        group_id_size,
        key_package_batch_size,
    )
    encrypted_group_info = opaque_len(group_info + suite.aead_tag_len)
    return MLS_MESSAGE_HEADER_LEN + CIPHERSUITE_LEN + secrets + encrypted_group_info


def slim_welcome_message_len(
    suite: CipherSuite,
    tree_mode: str,
    group_size: int,
    credential_size: int,
    group_id_size: int,
    key_package_batch_size: int,
) -> int:
    encrypted_group_secrets = (
        ENUM_LEN  # RecipientIdentifierType
        + LEAF_INDEX_LEN
        + hpke_ciphertext_len(suite, group_secrets_plaintext_len(suite))
    )
    secrets = vector_len([encrypted_group_secrets])
    group_info = group_info_len(
        suite,
        "slim",
        tree_mode,
        group_size,
        credential_size,
        group_id_size,
        key_package_batch_size,
    )
    group_info_present = 1  # optional<WelcomeGroupInfo> presence byte.
    plaintext_group_info_type = ENUM_LEN
    return (
        MLS_MESSAGE_HEADER_LEN
        + CIPHERSUITE_LEN
        + secrets
        + group_info_present
        + plaintext_group_info_type
        + group_info
    )


def copath_update_public_key_count(tree_mode: str, group_size: int) -> int:
    if tree_mode == "sparse":
        return 0
    return path_node_count(group_size)


def large_object_carrier_len(
    suite: CipherSuite,
    hpke_public_key_count: int = 0,
    signature_public_key_count: int = 0,
    credential_sizes: Iterable[int] | None = None,
    hpke_ciphertext_plaintext_lens: Iterable[int] | None = None,
    signature_count: int = 0,
) -> int:
    credential_sizes = list(credential_sizes or [])
    hpke_ciphertext_plaintext_lens = list(hpke_ciphertext_plaintext_lens or [])
    if (
        hpke_public_key_count == 0
        and signature_public_key_count == 0
        and not credential_sizes
        and not hpke_ciphertext_plaintext_lens
        and signature_count == 0
    ):
        return 0

    hpke_public_keys = vector_len(
        [hpke_public_key_len(suite)] * hpke_public_key_count
    )
    signature_public_keys = vector_len(
        [signature_public_key_len(suite)] * signature_public_key_count
    )
    credentials = vector_len(credential_sizes)
    hpke_ciphertexts = vector_len(
        [
            hpke_ciphertext_len(suite, plaintext_len)
            for plaintext_len in hpke_ciphertext_plaintext_lens
        ]
    )
    signatures = vector_len([signature_len(suite)] * signature_count)
    return (
        hpke_public_keys
        + signature_public_keys
        + credentials
        + hpke_ciphertexts
        + signatures
    )


def slim_welcome_carrier_len(
    suite: CipherSuite,
    tree_mode: str,
    group_size: int,
    credential_size: int,
    delivery_capability: str,
) -> int:
    # Basic processing validates the slim tree and derives epoch secrets. Sending
    # an update path additionally requires the new member's copath HPKE keys.
    hpke_public_key_count = 0
    if delivery_capability == UPDATE_DELIVERY:
        hpke_public_key_count = copath_update_public_key_count(tree_mode, group_size)
    tree_leaf_count = 0 if tree_mode == "sparse" else group_size
    signature_public_key_count = tree_leaf_count
    credential_sizes = [credential_size] * tree_leaf_count
    # The plaintext SlimGroupInfo signature is a SignatureRef. In a full tree,
    # each SlimLeafNode also carries a SignatureRef.
    signature_count = 1 + tree_leaf_count
    return large_object_carrier_len(
        suite,
        hpke_public_key_count=hpke_public_key_count,
        signature_public_key_count=signature_public_key_count,
        credential_sizes=credential_sizes,
        signature_count=signature_count,
    )


def framed_content_prefix_len(
    group_id_size: int, authenticated_data_size: int
) -> int:
    group_id = opaque_len(group_id_size)
    epoch = GROUP_EPOCH_LEN
    sender_member = SENDER_TYPE_LEN + LEAF_INDEX_LEN
    authenticated_data = opaque_len(authenticated_data_size)
    content_type = CONTENT_TYPE_LEN
    return group_id + epoch + sender_member + authenticated_data + content_type


def proposal_refs_len(suite: CipherSuite, commit_proposal_refs: int) -> int:
    if commit_proposal_refs == 0:
        return empty_vector_len()
    proposal_ref = ENUM_LEN + ref_len(suite)
    return vector_len([proposal_ref] * commit_proposal_refs)


def regular_update_path_node_len(
    suite: CipherSuite, ciphertext_count: int
) -> int:
    ciphertext = hpke_ciphertext_len(suite, suite.hash_len)
    # UpdatePathNode = HPKEPublicKey encryption_key plus encrypted_path_secret<V>.
    return hpke_public_key_len(suite) + vector_len([ciphertext] * ciphertext_count)


def regular_public_commit_message_len(
    suite: CipherSuite,
    tree_mode: str,
    group_size: int,
    credential_size: int,
    group_id_size: int,
    authenticated_data_size: int,
    commit_proposal_refs: int,
) -> int:
    path_nodes = path_node_count(group_size)
    ciphertext_count = 0 if tree_mode == "sparse" else 1
    update_path_nodes = vector_len(
        [regular_update_path_node_len(suite, ciphertext_count)] * path_nodes
    )
    update_path = (
        regular_leaf_node_len(suite, credential_size, "commit") + update_path_nodes
    )
    # Commit = proposals<V> plus optional<UpdatePath>.
    commit = proposal_refs_len(suite, commit_proposal_refs) + optional_len(update_path)
    framed_content = (
        framed_content_prefix_len(group_id_size, authenticated_data_size) + commit
    )
    auth = signature_len(suite) + mac_len(suite)
    membership_tag = mac_len(suite)
    return MLS_MESSAGE_HEADER_LEN + framed_content + auth + membership_tag


def slim_update_path_node_len(
    suite: CipherSuite, ciphertext_ref_count: int
) -> int:
    # SlimUpdatePathNode = HPKEPublicKeyRef plus HPKECiphertextRef vector.
    return ref_len(suite) + vector_len([ref_len(suite)] * ciphertext_ref_count)


def slim_update_path_len(
    suite: CipherSuite, tree_mode: str, group_size: int, recipient_view: bool
) -> int:
    path_nodes = path_node_count(group_size)

    if tree_mode == "sparse":
        return vector_len([slim_update_path_node_len(suite, 0)] * path_nodes)

    if not recipient_view:
        # Sender-to-DS carries one ciphertext reference for each path node.
        return vector_len([slim_update_path_node_len(suite, 1)] * path_nodes)

    if path_nodes == 0:
        return vector_len([])

    nodes = [slim_update_path_node_len(suite, 1)]
    # DS-to-member delivery keeps all public-key refs but only the one
    # ciphertext ref needed by that recipient.
    nodes.extend([slim_update_path_node_len(suite, 0)] * (path_nodes - 1))
    return vector_len(nodes)


def slim_public_commit_message_len(
    suite: CipherSuite,
    tree_mode: str,
    group_size: int,
    group_id_size: int,
    authenticated_data_size: int,
    recipient_view: bool,
    key_package_batch_size: int,
    commit_proposal_refs: int,
    slim_commit_auth: str,
) -> int:
    commit_leaf = slim_leaf_node_len(
        suite,
        "commit",
        has_outer_hash=True,
        key_package_batch_size=key_package_batch_size,
    )
    # SlimCommit = proposals<V> plus optional<SlimLeafNode>.
    slim_commit = proposal_refs_len(suite, commit_proposal_refs) + optional_len(
        commit_leaf
    )
    framed_content = (
        framed_content_prefix_len(group_id_size, authenticated_data_size)
        + slim_commit
    )
    if slim_commit_auth == SLIM_COMMIT_SINGLE_SIGNATURE:
        auth = optional_len(None) + mac_len(suite)
    elif slim_commit_auth == SLIM_COMMIT_FRAMING_SIGNATURE:
        signature_or_ref = ENUM_LEN + ref_len(suite)
        auth = optional_len(signature_or_ref) + mac_len(suite)
    else:
        raise ValueError(f"unknown SlimCommit auth mode: {slim_commit_auth}")
    membership_tag = mac_len(suite)
    update_path = optional_len(
        slim_update_path_len(suite, tree_mode, group_size, recipient_view)
    )
    return (
        MLS_MESSAGE_HEADER_LEN
        + framed_content
        + auth
        + membership_tag
        + update_path
    )


def slim_commit_sender_carrier_len(
    suite: CipherSuite, tree_mode: str, group_size: int, slim_commit_auth: str
) -> int:
    path_nodes = path_node_count(group_size)
    # The sender provides the new leaf HPKE key plus one HPKE public key per
    # path node.
    hpke_public_key_count = path_nodes + 1
    ciphertext_count = 0 if tree_mode == "sparse" else path_nodes
    signature_count = 1
    if slim_commit_auth == SLIM_COMMIT_FRAMING_SIGNATURE:
        signature_count += 1
    return large_object_carrier_len(
        suite,
        hpke_public_key_count=hpke_public_key_count,
        hpke_ciphertext_plaintext_lens=[suite.hash_len] * ciphertext_count,
        signature_count=signature_count,
    )


def slim_commit_member_carrier_len(
    suite: CipherSuite,
    tree_mode: str,
    group_size: int,
    delivery_capability: str,
    slim_commit_auth: str,
) -> int:
    path_nodes = path_node_count(group_size)
    ciphertext_count = 0
    if tree_mode == "full" and path_nodes > 0:
        ciphertext_count = 1
    hpke_public_key_count = 0
    if (
        tree_mode == "full"
        and delivery_capability == UPDATE_DELIVERY
        and path_nodes > 0
    ):
        # Each receiver has exactly one updated committer-side node in its
        # copath. Basic processing only needs the ref; sending an update without
        # a later fetch needs the actual HPKE public key.
        hpke_public_key_count = 1
    signature_count = 1
    if slim_commit_auth == SLIM_COMMIT_FRAMING_SIGNATURE:
        signature_count += 1
    return large_object_carrier_len(
        suite,
        hpke_public_key_count=hpke_public_key_count,
        hpke_ciphertext_plaintext_lens=[suite.hash_len] * ciphertext_count,
        signature_count=signature_count,
    )


def compute_sizes(
    suite: CipherSuite,
    protocol: str,
    tree_mode: str,
    group_size: int,
    credential_size: int,
    group_id_size: int,
    authenticated_data_size: int,
    delivery_capability: str,
    key_package_batch_size: int,
    commit_proposal_refs: int,
    slim_commit_auth: str,
) -> MessageSizes:
    if protocol == "regular":
        welcome_message = regular_welcome_message_len(
            suite,
            tree_mode,
            group_size,
            credential_size,
            group_id_size,
            key_package_batch_size,
        )
        commit_message = regular_public_commit_message_len(
            suite,
            tree_mode,
            group_size,
            credential_size,
            group_id_size,
            authenticated_data_size,
            commit_proposal_refs,
        )
        return MessageSizes(
            welcome_message=welcome_message,
            welcome_carrier=0,
            commit_sender_message=commit_message,
            commit_sender_carrier=0,
            commit_member_message=commit_message,
            commit_member_carrier=0,
            path_nodes=path_node_count(group_size),
        )

    if protocol == "slim":
        return MessageSizes(
            welcome_message=slim_welcome_message_len(
                suite,
                tree_mode,
                group_size,
                credential_size,
                group_id_size,
                key_package_batch_size,
            ),
            welcome_carrier=slim_welcome_carrier_len(
                suite,
                tree_mode,
                group_size,
                credential_size,
                delivery_capability,
            ),
            commit_sender_message=slim_public_commit_message_len(
                suite,
                tree_mode,
                group_size,
                group_id_size,
                authenticated_data_size,
                recipient_view=False,
                key_package_batch_size=key_package_batch_size,
                commit_proposal_refs=commit_proposal_refs,
                slim_commit_auth=slim_commit_auth,
            ),
            commit_sender_carrier=slim_commit_sender_carrier_len(
                suite, tree_mode, group_size, slim_commit_auth
            ),
            commit_member_message=slim_public_commit_message_len(
                suite,
                tree_mode,
                group_size,
                group_id_size,
                authenticated_data_size,
                recipient_view=True,
                key_package_batch_size=key_package_batch_size,
                commit_proposal_refs=commit_proposal_refs,
                slim_commit_auth=slim_commit_auth,
            ),
            commit_member_carrier=slim_commit_member_carrier_len(
                suite,
                tree_mode,
                group_size,
                delivery_capability,
                slim_commit_auth,
            ),
            path_nodes=path_node_count(group_size),
        )

    raise ValueError(f"unknown protocol: {protocol}")


def parse_csv(values: list[str] | None, default: list[str]) -> list[str]:
    if not values:
        return default
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def parse_int_csv(values: list[str] | None, default: list[int]) -> list[int]:
    parsed = parse_csv(values, [str(value) for value in default])
    result = []
    for value in parsed:
        try:
            integer = int(value)
        except ValueError:
            raise ValueError(f"not an integer: {value}") from None
        if integer < 0:
            raise ValueError(f"must be non-negative: {value}")
        result.append(integer)
    return result


def validate_choices(values: list[str], allowed: set[str], option_name: str) -> None:
    invalid = [value for value in values if value not in allowed]
    if invalid:
        allowed_values = ", ".join(sorted(allowed))
        invalid_values = ", ".join(invalid)
        raise ValueError(
            f"{option_name} has invalid value(s): {invalid_values}. "
            f"Allowed values: {allowed_values}"
        )


def parse_custom_ciphersuites(values: list[str] | None) -> list[CipherSuite]:
    suites = []
    for value in values or []:
        parts = value.split(":")
        if len(parts) not in (6, 7):
            raise argparse.ArgumentTypeError(
                "--custom-ciphersuite must be "
                "NAME:HASH_LEN:HPKE_PK:HPKE_KEM_OUTPUT:SIG_PK:SIG[:AEAD_TAG]"
            )
        name = parts[0]
        try:
            numbers = [int(part) for part in parts[1:]]
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"invalid custom ciphersuite numeric field: {value}"
            ) from None
        if any(number < 0 for number in numbers):
            raise argparse.ArgumentTypeError(
                f"custom ciphersuite values must be non-negative: {value}"
            )
        if len(numbers) == 5:
            numbers.append(16)
        suites.append(
            CipherSuite(
                name=name,
                hash_len=numbers[0],
                hpke_public_key_len=numbers[1],
                hpke_kem_output_len=numbers[2],
                signature_public_key_len=numbers[3],
                signature_len=numbers[4],
                aead_tag_len=numbers[5],
                note="Custom ciphersuite supplied on the command line.",
            )
        )
    return suites


def resolve_ciphersuites(names: list[str], custom: list[CipherSuite]) -> list[CipherSuite]:
    resolved = []
    custom_by_name = {suite.name.lower(): suite for suite in custom}
    for name in names:
        key = name.lower()
        if key in custom_by_name:
            resolved.append(custom_by_name[key])
        elif key in SUPPORTED_CIPHERSUITES:
            resolved.append(SUPPORTED_CIPHERSUITES[key])
        else:
            known = ", ".join(sorted(set(SUPPORTED_CIPHERSUITES)))
            raise SystemExit(f"unknown ciphersuite '{name}'. Known aliases: {known}")

    seen = set()
    deduped = []
    for suite in resolved:
        if suite.name not in seen:
            deduped.append(suite)
            seen.add(suite.name)
    return deduped


def format_int(value: int) -> str:
    return f"{value:,}"


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    output = []
    output.append("| " + " | ".join(headers) + " |")
    output.append("|" + "|".join("---" for _ in headers) + "|")
    output.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(output)


def generate_markdown(
    suites: list[CipherSuite],
    protocols: list[str],
    tree_modes: list[str],
    delivery_capabilities: list[str],
    group_sizes: list[int],
    credential_sizes: list[int],
    group_id_size: int,
    authenticated_data_size: int,
    key_package_batch_size: int,
    commit_proposal_refs: int,
    slim_commit_auth: str,
    table_format: str,
) -> str:
    lines = [
        "# MLS message-size matrix",
        "",
        f"Generated: {_dt.date.today().isoformat()}",
        "",
        "## Parameters",
        "",
        f"- Ciphersuites: {', '.join(f'`{suite.name}`' for suite in suites)}",
        f"- Protocol modes: {', '.join(f'`{protocol}`' for protocol in protocols)}",
        f"- Tree modes: {', '.join(f'`{tree}`' for tree in tree_modes)}",
        "- Delivery capabilities: "
        + ", ".join(f"`{capability}`" for capability in delivery_capabilities),
        f"- Group sizes: {', '.join(format_int(size) for size in group_sizes)}",
        "- Credential sizes: "
        + ", ".join(f"{format_int(size)} encoded bytes" for size in credential_sizes),
        f"- Group ID size: {format_int(group_id_size)} bytes",
        f"- Authenticated data size: {format_int(authenticated_data_size)} bytes",
        f"- Key-package batch size: {format_int(key_package_batch_size)}",
        f"- Commit proposal references: {format_int(commit_proposal_refs)}",
        f"- SlimCommit authentication: `{slim_commit_auth}`",
        "",
        "## Ciphersuite object sizes",
        "",
    ]

    suite_rows = []
    for suite in suites:
        suite_rows.append(
            [
                f"`{suite.name}`",
                format_int(suite.hash_len),
                format_int(suite.hpke_public_key_len),
                format_int(suite.hpke_kem_output_len),
                format_int(suite.signature_public_key_len),
                format_int(suite.signature_len),
                format_int(suite.aead_tag_len),
                suite.note,
            ]
        )
    lines.append(
        markdown_table(
            [
                "Ciphersuite",
                "Hash",
                "HPKE pk",
                "HPKE enc",
                "Sig pk",
                "Signature",
                "AEAD tag",
                "Note",
            ],
            suite_rows,
        )
    )

    lines.extend(
        [
            "",
            "## Model notes",
            "",
            "- `regular` is RFC 9420-style MLS framing. The Welcome carries an "
            "encrypted GroupInfo and a ratchet_tree extension; the Commit carries "
            "the full UpdatePath in the PublicMessage.",
            "- `slim` is the SlimMLS framing in this repo. The Welcome carries a "
            "plaintext GroupInfo supplied by the DS, one per-recipient secret, and "
            "a Large Object Carrier for signature public keys, credentials, and "
            "referenced signatures. The Commit uses a split SlimUpdatePath and "
            "per-recipient DS reduction.",
            "- Welcome and Commit sizes are independent cases. With the default "
            "`Commit proposal references: 0`, the Commit is a self-update with an "
            "empty proposal list, not the Add Commit that produces the Welcome.",
            "- Increase `--commit-proposal-ref` to model Commits that cover "
            "previously sent proposals by reference. One reference is sufficient "
            "for an Add-by-reference Commit that produces a Welcome.",
            "- `basic` delivery is enough to process Welcomes and Commits, receive "
            "later messages, and send application messages. It may omit HPKE public "
            "keys that are only needed to construct a future update path.",
            "- `update` delivery additionally includes the HPKE public keys needed "
            "to send an update with no later fetch: the joiner's copath keys for "
            "Welcomes, and one updated copath key for each SlimMLS commit receiver.",
            "- A SlimMLS DS-to-member Commit always contains HPKE public-key "
            "references for the update path. In `basic` delivery, its carrier "
            "contains only the one HPKE ciphertext the recipient needs.",
            "- `full` means every leaf and parent in the ratchet tree extension is "
            "non-blank. For update paths, this model assumes one encrypted path "
            "secret per path node before SlimMLS DS reduction.",
            "- `sparse` is a mechanical size case where every ratchet tree node is "
            "blank. It is useful for measuring tree-extension overhead, but it is "
            "not a valid representation of an actual group with that many members.",
            "- Path-node count is `ceil(log2(group_size))`. In a real left-balanced "
            "tree, some right-edge leaves can have a shorter direct path.",
            "- SlimMLS key-package leaves include the required OuterKeyPackageHash "
            "app-data component. SlimMLS commit leaves include the required "
            "OuterUpdateHash app-data component.",
            "- SlimMLS key-package leaves include a SlimKeyPackageMerkleProof. "
            "The proof path is modeled with `ceil(log2(key-package batch size))` "
            "sibling hashes.",
            "- SlimMLS leaves advertise the `slim_mls` GroupContext extension. "
            "Leaves carrying app-data components also advertise the "
            "`app_data_dictionary` LeafNode extension.",
            "- SlimMLS plaintext GroupInfo, SlimLeafNode, and public-message "
            "framing signatures are modeled as SignatureRef values in messages; "
            "the referenced raw signatures are counted in the Large Object "
            "Carrier when needed.",
            "- `single-signature` SlimCommit authentication applies only to member "
            "Commits with a SlimLeafNode and an unchanged signature key. Use "
            "`--slim-commit-auth framing-signature` for cases that require the "
            "normal framing signature.",
            "- Commit aggregate is "
            "`sender-to-DS total + (group_size - 1) * DS-to-member total`.",
            "",
            "## Size tables",
            "",
        ]
    )

    full_headers = [
        "Credential",
        "Group",
        "Path nodes",
        "Welcome msg",
        "Welcome carrier",
        "Welcome total",
        "Commit sender msg",
        "Commit sender carrier",
        "Commit sender total",
        "Commit member msg",
        "Commit member carrier",
        "Commit member total",
        "Commit aggregate",
    ]
    compact_headers = [
        "Group",
        "Welcome total",
        "Commit sender total",
        "Commit member total",
    ]

    for suite, protocol, tree_mode, delivery_capability in itertools.product(
        suites, protocols, tree_modes, delivery_capabilities
    ):
        delivery_label = f" / delivery `{delivery_capability}`"
        if table_format == "compact":
            for credential_size in credential_sizes:
                lines.append(
                    f"### `{suite.name}` / `{protocol}` / `{tree_mode}`"
                    f"{delivery_label} / "
                    f"credential {format_int(credential_size)} B"
                )
                lines.append("")
                rows = []
                for group_size in group_sizes:
                    sizes = compute_sizes(
                        suite=suite,
                        protocol=protocol,
                        tree_mode=tree_mode,
                        group_size=group_size,
                        credential_size=credential_size,
                        group_id_size=group_id_size,
                        authenticated_data_size=authenticated_data_size,
                        delivery_capability=delivery_capability,
                        key_package_batch_size=key_package_batch_size,
                        commit_proposal_refs=commit_proposal_refs,
                        slim_commit_auth=slim_commit_auth,
                    )
                    rows.append(
                        [
                            format_int(group_size),
                            format_int(sizes.welcome_total),
                            format_int(sizes.commit_sender_total),
                            format_int(sizes.commit_member_total),
                        ]
                    )
                lines.append(markdown_table(compact_headers, rows))
                lines.append("")
            continue

        lines.append(
            f"### `{suite.name}` / `{protocol}` / `{tree_mode}`{delivery_label}"
        )
        lines.append("")
        rows = []
        for credential_size, group_size in itertools.product(
            credential_sizes, group_sizes
        ):
            sizes = compute_sizes(
                suite=suite,
                protocol=protocol,
                tree_mode=tree_mode,
                group_size=group_size,
                credential_size=credential_size,
                group_id_size=group_id_size,
                authenticated_data_size=authenticated_data_size,
                delivery_capability=delivery_capability,
                key_package_batch_size=key_package_batch_size,
                commit_proposal_refs=commit_proposal_refs,
                slim_commit_auth=slim_commit_auth,
            )
            rows.append(
                [
                    format_int(credential_size),
                    format_int(group_size),
                    format_int(sizes.path_nodes),
                    format_int(sizes.welcome_message),
                    format_int(sizes.welcome_carrier),
                    format_int(sizes.welcome_total),
                    format_int(sizes.commit_sender_message),
                    format_int(sizes.commit_sender_carrier),
                    format_int(sizes.commit_sender_total),
                    format_int(sizes.commit_member_message),
                    format_int(sizes.commit_member_carrier),
                    format_int(sizes.commit_member_total),
                    format_int(sizes.commit_aggregate(group_size)),
                ]
            )
        lines.append(markdown_table(full_headers, rows))
        lines.append("")

    return "\n".join(lines)


def list_ciphersuites() -> str:
    unique = {}
    for suite in SUPPORTED_CIPHERSUITES.values():
        unique[suite.name] = suite
    rows = []
    for suite in sorted(unique.values(), key=lambda item: item.name):
        aliases = sorted(
            alias
            for alias, aliased_suite in SUPPORTED_CIPHERSUITES.items()
            if aliased_suite == suite
        )
        rows.append(
            [
                f"`{suite.name}`",
                ", ".join(f"`{alias}`" for alias in aliases),
                str(suite.hash_len),
                str(suite.hpke_public_key_len),
                str(suite.hpke_kem_output_len),
                str(suite.signature_public_key_len),
                str(suite.signature_len),
            ]
        )
    return markdown_table(
        [
            "Ciphersuite",
            "Aliases",
            "Hash",
            "HPKE pk",
            "HPKE enc",
            "Sig pk",
            "Sig",
        ],
        rows,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compute a markdown matrix of approximate RFC 9420 MLS and SlimMLS "
            "Welcome and public Commit sizes."
        )
    )
    parser.add_argument(
        "--ciphersuite",
        action="append",
        help=(
            "Ciphersuite alias or full name. Can be repeated or comma-separated. "
            "Default: mti"
        ),
    )
    parser.add_argument(
        "--custom-ciphersuite",
        action="append",
        help=(
            "Add a ciphersuite as "
            "NAME:HASH_LEN:HPKE_PK:HPKE_KEM_OUTPUT:SIG_PK:SIG[:AEAD_TAG]. "
            "Then select it with --ciphersuite NAME."
        ),
    )
    parser.add_argument(
        "--credential-size",
        action="append",
        help=(
            "Encoded Credential size in bytes. Can be repeated or comma-separated. "
            "Default: 19, matching a basic credential with a 16-byte identity."
        ),
    )
    parser.add_argument(
        "--group-size",
        action="append",
        help="Group size. Can be repeated or comma-separated. Default: 100.",
    )
    parser.add_argument(
        "--protocol",
        action="append",
        help=(
            "Protocol mode. Can be repeated or comma-separated. Use both values "
            "for comparison. Default: slim. Choices: regular, slim."
        ),
    )
    parser.add_argument(
        "--tree",
        action="append",
        help=(
            "Tree mode. Can be repeated or comma-separated. In sparse mode all "
            "tree nodes are blank. Default: full. Choices: full, sparse."
        ),
    )
    parser.add_argument(
        "--delivery",
        action="append",
        help=(
            "Delivery capability. Can be repeated or comma-separated. 'basic' is "
            "enough to process messages and send application messages. 'update' "
            "also includes public keys needed to send an update path without a "
            "later fetch. Default: update. Choices: basic, update."
        ),
    )
    parser.add_argument(
        "--group-id-size",
        type=int,
        default=16,
        help="Group ID size in bytes. Default: 16.",
    )
    parser.add_argument(
        "--authenticated-data-size",
        type=int,
        default=0,
        help="Authenticated data size in bytes for commits. Default: 0.",
    )
    parser.add_argument(
        "--key-package-batch-size",
        type=int,
        default=1,
        help=(
            "SlimKeyPackage batch size used to estimate Merkle proof path "
            "lengths. Default: 1."
        ),
    )
    parser.add_argument(
        "--commit-proposal-ref",
        type=int,
        default=0,
        help=(
            "Number of ProposalOrRef.reference entries in modeled Commits. "
            "Default: 0, a self-update Commit."
        ),
    )
    parser.add_argument(
        "--slim-commit-auth",
        choices=sorted(SLIM_COMMIT_AUTH_MODES),
        default=SLIM_COMMIT_SINGLE_SIGNATURE,
        help=(
            "SlimCommit authentication model. Default: single-signature. Use "
            "framing-signature when the SlimMLS single-signature construction "
            "does not apply."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("message-size-matrix.md"),
        help="Markdown output path. Default: message-size-matrix.md.",
    )
    parser.add_argument(
        "--table",
        choices=["full", "compact"],
        default="full",
        help=(
            "Output table format. 'compact' only includes Group, Welcome total, "
            "commit sender total, and commit member total. Default: full."
        ),
    )
    parser.add_argument(
        "--list-ciphersuites",
        action="store_true",
        help="Print built-in ciphersuite presets and exit.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.list_ciphersuites:
        print(list_ciphersuites())
        return 0

    if args.group_id_size < 0 or args.authenticated_data_size < 0:
        parser.error("--group-id-size and --authenticated-data-size must be non-negative")
    if args.key_package_batch_size < 1:
        parser.error("--key-package-batch-size must be at least 1")
    if args.commit_proposal_ref < 0:
        parser.error("--commit-proposal-ref must be non-negative")

    custom = parse_custom_ciphersuites(args.custom_ciphersuite)
    ciphersuite_names = parse_csv(args.ciphersuite, ["mti"])
    suites = resolve_ciphersuites(ciphersuite_names, custom)
    protocols = parse_csv(args.protocol, ["slim"])
    tree_modes = parse_csv(args.tree, ["full"])
    delivery_capabilities = parse_csv(args.delivery, [UPDATE_DELIVERY])
    try:
        validate_choices(protocols, {"regular", "slim"}, "--protocol")
        validate_choices(tree_modes, {"full", "sparse"}, "--tree")
        validate_choices(
            delivery_capabilities, DELIVERY_CAPABILITIES, "--delivery"
        )
        group_sizes = parse_int_csv(args.group_size, [100])
        credential_sizes = parse_int_csv(args.credential_size, [19])
    except ValueError as error:
        parser.error(str(error))

    for group_size in group_sizes:
        if group_size < 1:
            parser.error("--group-size must be at least 1")

    markdown = generate_markdown(
        suites=suites,
        protocols=protocols,
        tree_modes=tree_modes,
        delivery_capabilities=delivery_capabilities,
        group_sizes=group_sizes,
        credential_sizes=credential_sizes,
        group_id_size=args.group_id_size,
        authenticated_data_size=args.authenticated_data_size,
        key_package_batch_size=args.key_package_batch_size,
        commit_proposal_refs=args.commit_proposal_ref,
        slim_commit_auth=args.slim_commit_auth,
        table_format=args.table,
    )
    args.output.write_text(markdown + "\n", encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
