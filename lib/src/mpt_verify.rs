//! Proof verification logic.
//!
//! This module is heavily copied from <https://github.com/alloy-rs/trie>.

use alloy_primitives::{Bytes, B256};
use alloy_rlp::{Decodable, EMPTY_STRING_CODE};
use alloy_trie::{
    nodes::{BranchNode, RlpNode, TrieNode, CHILD_INDEX_RANGE},
    proof::ProofVerificationError,
    EMPTY_ROOT_HASH,
};
use core::ops::Deref;
use nybbles::Nibbles;
use std::iter;

pub struct VerifiedNode<'a> {
    pub n_nibbles: usize,
    pub node: &'a Bytes,
}

#[derive(Default)]
pub struct VerifiedNodeStack<'a> {
    key: Nibbles,
    nodes: Vec<VerifiedNode<'a>>,
}

fn is_prefix(a: &Nibbles, b: &Nibbles, prefix_len: usize) -> bool {
    prefix_len <= b.len()
        && iter::zip(&a[..prefix_len], &b[..prefix_len])
            .rev()
            .all(|(a, b)| a == b)
}

impl VerifiedNodeStack<'_> {
    fn unwind(&mut self, key: Nibbles) {
        while let Some(node) = self.nodes.last() {
            if is_prefix(&self.key, &key, node.n_nibbles) {
                break;
            }
            let _ = self.nodes.pop();
        }
        self.key = key;
    }

    fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

pub fn verify_proof_stateful<'a, I>(
    root: B256,
    key: Nibbles,
    expected_value: Option<Vec<u8>>,
    proof: I,
    verify_stack: &mut VerifiedNodeStack<'a>,
) -> Result<(), ProofVerificationError>
where
    I: IntoIterator<Item = &'a Bytes>,
{
    let mut proof = proof.into_iter();

    if verify_stack.is_empty() {
        let first_node = proof.next();

        // If the proof is empty or contains only an empty node, the expected value must be None.
        // If the proof is empty or contains only an empty node, the expected value must be None.
        if first_node.map_or(true, |node| node.as_ref() == [EMPTY_STRING_CODE]) {
            return if root == EMPTY_ROOT_HASH {
                if expected_value.is_none() {
                    Ok(())
                } else {
                    Err(ProofVerificationError::ValueMismatch {
                        path: key,
                        got: None,
                        expected: expected_value.map(Bytes::from),
                    })
                }
            } else {
                Err(ProofVerificationError::RootMismatch {
                    got: EMPTY_ROOT_HASH,
                    expected: root,
                })
            };
        }

        let first_node = first_node.expect("first_node empty condition checked above");

        // Check if the root node matches the expected node from the proof.
        if RlpNode::from_rlp(first_node) != RlpNode::word_rlp(&root) {
            let got = Some(Bytes::copy_from_slice(first_node));
            let expected = Some(Bytes::copy_from_slice(&RlpNode::word_rlp(&root)));
            return Err(ProofVerificationError::ValueMismatch {
                path: Nibbles::new(),
                got,
                expected,
            });
        }

        verify_stack.key = key.clone();
        verify_stack.nodes.push(VerifiedNode {
            n_nibbles: 0,
            node: first_node,
        });
    } else {
        verify_stack.unwind(key.clone());
    }

    let mut walked_path = Nibbles::with_capacity(key.len());
    let mut last_decoded_node = None;

    if let Some(last_stack_node) = verify_stack.nodes.last() {
        walked_path.extend_from_slice_unchecked(&verify_stack.key[..last_stack_node.n_nibbles]);

        // Decode the last node from the stack.
        last_decoded_node = match TrieNode::decode(&mut &last_stack_node.node[..])? {
            TrieNode::Branch(branch) => process_branch(branch, &mut walked_path, &key)?,
            TrieNode::Extension(extension) => {
                walked_path.extend_from_slice(&extension.key);
                Some(NodeDecodingResult::Node(extension.child))
            }
            TrieNode::Leaf(leaf) => {
                walked_path.extend_from_slice(&leaf.key);
                Some(NodeDecodingResult::Value(leaf.value))
            }
            TrieNode::EmptyRoot => return Err(ProofVerificationError::UnexpectedEmptyRoot),
        };
    }

    for node in proof {
        // Check if the node that we just decoded (or root node, if we just started) matches
        // the expected node from the proof.
        if Some(RlpNode::from_rlp(node).as_slice()) != last_decoded_node.as_deref() {
            let got = Some(Bytes::copy_from_slice(node));
            let expected = last_decoded_node.as_deref().map(Bytes::copy_from_slice);
            return Err(ProofVerificationError::ValueMismatch {
                path: walked_path,
                got,
                expected,
            });
        }

        verify_stack.nodes.push(VerifiedNode {
            n_nibbles: walked_path.len(),
            node,
        });

        let node = &verify_stack.nodes.last().expect("node just pushed").node;

        // Decode the next node from the proof.
        last_decoded_node = match TrieNode::decode(&mut &node[..])? {
            TrieNode::Branch(branch) => process_branch(branch, &mut walked_path, &key)?,
            TrieNode::Extension(extension) => {
                walked_path.extend_from_slice(&extension.key);
                Some(NodeDecodingResult::Node(extension.child))
            }
            TrieNode::Leaf(leaf) => {
                walked_path.extend_from_slice(&leaf.key);
                Some(NodeDecodingResult::Value(leaf.value))
            }
            TrieNode::EmptyRoot => return Err(ProofVerificationError::UnexpectedEmptyRoot),
        };
    }

    // Last decoded node should have the key that we are looking for.
    last_decoded_node = last_decoded_node.filter(|_| walked_path == key);
    if last_decoded_node.as_deref() == expected_value.as_deref() {
        Ok(())
    } else {
        Err(ProofVerificationError::ValueMismatch {
            path: key,
            got: last_decoded_node.as_deref().map(Bytes::copy_from_slice),
            expected: expected_value.map(Bytes::from),
        })
    }
}

/// Verify the proof for given key value pair against the provided state root.
///
/// The expected node value can be either [Some] if it's expected to be present
/// in the tree or [None] if this is an exclusion proof.
#[allow(unused)]
pub fn verify_proof<'a, I>(
    root: B256,
    key: Nibbles,
    expected_value: Option<Vec<u8>>,
    proof: I,
) -> Result<(), ProofVerificationError>
where
    I: IntoIterator<Item = &'a Bytes>,
{
    let mut stack = VerifiedNodeStack {
        key: Nibbles::default(),
        nodes: Vec::new(),
    };
    verify_proof_stateful(root, key, expected_value, proof, &mut stack)
}

/// The result of decoding a node from the proof.
///
/// - [`TrieNode::Branch`] is decoded into a [`NodeDecodingResult::Value`] if the node at the
///   specified nibble was decoded into an in-place encoded [`TrieNode::Leaf`], or into a
///   [`NodeDecodingResult::Node`] otherwise.
/// - [`TrieNode::Extension`] is always decoded into a [`NodeDecodingResult::Node`].
/// - [`TrieNode::Leaf`] is always decoded into a [`NodeDecodingResult::Value`].
#[derive(Debug, PartialEq, Eq)]
enum NodeDecodingResult {
    Node(RlpNode),
    Value(Vec<u8>),
}

impl Deref for NodeDecodingResult {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Node(node) => node.as_slice(),
            Self::Value(value) => value,
        }
    }
}

#[inline]
fn process_branch(
    mut branch: BranchNode,
    walked_path: &mut Nibbles,
    key: &Nibbles,
) -> Result<Option<NodeDecodingResult>, ProofVerificationError> {
    if let Some(next) = key.get(walked_path.len()) {
        let mut stack_ptr = branch.as_ref().first_child_index();
        for index in CHILD_INDEX_RANGE {
            if branch.state_mask.is_bit_set(index) {
                if index == *next {
                    walked_path.push(*next);

                    let child = branch.stack.remove(stack_ptr);
                    if child.len() == B256::len_bytes() + 1 {
                        return Ok(Some(NodeDecodingResult::Node(child)));
                    } else {
                        // This node is encoded in-place.
                        match TrieNode::decode(&mut &child[..])? {
                            TrieNode::Branch(child_branch) => {
                                // An in-place branch node can only have direct, also in-place
                                // encoded, leaf children, as anything else overflows this branch
                                // node, making it impossible to be encoded in-place in the first
                                // place.
                                return process_branch(child_branch, walked_path, key);
                            }
                            TrieNode::Extension(child_extension) => {
                                walked_path.extend_from_slice(&child_extension.key);

                                // If the extension node's child is a hash, the encoded extension
                                // node itself wouldn't fit for encoding in-place. So this extension
                                // node must have a child that is also encoded in-place.
                                //
                                // Since the child cannot be a leaf node (otherwise this node itself
                                // would be a leaf node, not an extension node), the child must be a
                                // branch node encoded in-place.
                                match TrieNode::decode(&mut &child_extension.child[..])? {
                                    TrieNode::Branch(extension_child_branch) => {
                                        return process_branch(
                                            extension_child_branch,
                                            walked_path,
                                            key,
                                        );
                                    }
                                    node @ (TrieNode::EmptyRoot
                                    | TrieNode::Extension(_)
                                    | TrieNode::Leaf(_)) => {
                                        unreachable!("unexpected extension node child: {node:?}")
                                    }
                                }
                            }
                            TrieNode::Leaf(child_leaf) => {
                                walked_path.extend_from_slice(&child_leaf.key);
                                return Ok(Some(NodeDecodingResult::Value(child_leaf.value)));
                            }
                            TrieNode::EmptyRoot => {
                                return Err(ProofVerificationError::UnexpectedEmptyRoot)
                            }
                        }
                    };
                }
                stack_ptr += 1;
            }
        }
    }

    Ok(None)
}
