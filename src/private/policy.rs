//! The one parent-scoped membership policy.
//!
//! The author runs it on its own pending commit before signing, and every
//! recipient runs it on the commit OpenMLS staged from the slot, before any
//! merge. It is deterministic in the authenticated parent state and the
//! signed transition: no recipient clock, local cutoff or trust preference is
//! consulted.
//!
//! OpenMLS enforces the MLS layer: signatures, membership tag, confirmation
//! tag, parent hashes, path decryption, tree and key uniqueness, and
//! KeyPackage validity at the supplied `VerifyAt` time. Everything below is
//! MassRelay's responsibility.

use openmls::prelude::*;

use super::binding::{BindingError, CredentialBinding, EndpointKey};
use super::codec::Hash;
use super::envelope::{Op, RosterEntry, SlotId, Transition, crypto, state_digest};
use super::{CIPHERSUITE, INVITE_WINDOW_SECS, KEY_PACKAGE_MAX_LIFETIME_SECS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// The candidate breaks a MassRelay rule. Confirmed invalid.
    Policy(String),
    /// A signature check rejected. Reported as an unconfirmed fault.
    Signature(String),
}

fn policy<T>(msg: impl Into<String>) -> Result<T, Violation> {
    Err(Violation::Policy(msg.into()))
}

impl From<BindingError> for Violation {
    fn from(e: BindingError) -> Self {
        match e {
            BindingError::Signature(s) => {
                Violation::Signature(format!("endpoint binding: {}", s.0))
            }
            other => Violation::Policy(format!("endpoint binding: {other:?}")),
        }
    }
}

/// Authenticated parent state a candidate is checked against.
pub struct ParentView<'a> {
    pub group: &'a MlsGroup,
    pub group_id: &'a [u8],
    pub group_tag: &'a Hash,
    pub relay_key: &'a [u8; 32],
    pub incarnation: &'a [u8],
    pub head: &'a Hash,
    pub revoked: &'a [EndpointKey],
}

/// Result of a candidate that passed the policy.
#[derive(Debug, Clone)]
pub struct Checked {
    pub roster: Vec<RosterEntry>,
    pub revoked: Vec<EndpointKey>,
    /// Resulting-state digest. `None` for a verified own removal, where
    /// OpenMLS cannot produce the resulting confirmed transcript hash.
    pub digest: Option<Hash>,
    pub self_removed: bool,
}

impl ParentView<'_> {
    /// Endpoint of a parent member. Parent bindings were verified when the
    /// member was admitted, and are verified again here.
    fn endpoint_of(&self, m: &Member) -> Result<EndpointKey, Violation> {
        Ok(CredentialBinding::verify_credential(
            &m.credential,
            &m.signature_key,
            self.group_tag,
        )?)
    }

    pub fn roster(&self) -> Result<Vec<RosterEntry>, Violation> {
        let mut r = vec![];
        for m in self.group.members() {
            r.push((self.endpoint_of(&m)?, m.signature_key.clone()));
        }
        r.sort();
        Ok(r)
    }

    /// Envelope-level checks before OpenMLS sees the commit. Returns the
    /// author's parent leaf signature key, which must verify the transition.
    pub fn check_envelope(&self, t: &Transition, slot: &SlotId) -> Result<Vec<u8>, Violation> {
        if &t.group_tag != self.group_tag {
            return policy("transition names another group");
        }
        if &t.relay_key != self.relay_key || t.incarnation != self.incarnation {
            return policy("transition names another relay or incarnation");
        }
        if &t.parent_head != self.head {
            return policy("transition names a different parent head");
        }
        if &t.slot != slot {
            return policy("transition bound to a different slot");
        }
        let author = self
            .group
            .members()
            .find(|m| m.index.u32() == t.author_leaf)
            .ok_or_else(|| Violation::Policy("author is not a parent member".into()))?;
        if self.endpoint_of(&author)? != t.author_endpoint {
            return policy("author endpoint differs from its parent leaf binding");
        }
        if let Op::Add {
            invite_not_before,
            invite_expires_at,
            reserved_at,
            ..
        } = &t.op
        {
            if invite_expires_at <= invite_not_before
                || invite_expires_at - invite_not_before > INVITE_WINDOW_SECS
            {
                return policy("signed invite window exceeds the cap");
            }
            if reserved_at < invite_not_before || reserved_at >= invite_expires_at {
                return policy("signed reservation is outside the signed invite window");
            }
            if reserved_at > &t.issued_at {
                return policy("signed reservation is after the signed commit time");
            }
        }
        Ok(author.signature_key)
    }

    /// MLS-level checks of a staged commit (the author's pending commit or a
    /// recipient's staged commit) against the signed transition.
    pub fn check_staged(
        &self,
        t: &Transition,
        staged: &StagedCommit,
    ) -> Result<Checked, Violation> {
        let props: Vec<&QueuedProposal> = staged.queued_proposals().collect();
        if props.len() != 1 {
            return policy(format!(
                "expected exactly one proposal, got {}",
                props.len()
            ));
        }
        let qp = props[0];
        if qp.proposal_or_ref_type() != ProposalOrRefType::Proposal {
            return policy("proposal by reference");
        }
        if qp.sender() != &Sender::Member(LeafNodeIndex::new(t.author_leaf)) {
            return policy(format!(
                "proposal sender {:?} is not the author",
                qp.sender()
            ));
        }
        // OpenMLS deduplicates identical proposals before `queued_proposals`
        // is built, so the count above cannot prove that the signed commit
        // carried exactly one. Cross-check the signed bytes.
        check_single_inline_proposal(&t.commit, qp.proposal())?;
        let parent: Vec<Member> = self.group.members().collect();
        let mut roster = self.roster()?;
        let mut revoked = self.revoked.to_vec();
        match (qp.proposal(), &t.op) {
            (
                Proposal::Add(add),
                Op::Add {
                    joiner,
                    transcript,
                    proof,
                    ..
                },
            ) => {
                let kp = add.key_package();
                let ln = kp.leaf_node();
                if kp.ciphersuite() != CIPHERSUITE {
                    return policy("KeyPackage ciphersuite");
                }
                let lt = kp.life_time();
                if lt.not_after() < lt.not_before()
                    || lt.not_after() - lt.not_before() > KEY_PACKAGE_MAX_LIFETIME_SECS
                    || !lt.has_acceptable_range()
                {
                    return policy("KeyPackage lifetime exceeds the cap");
                }
                let endpoint = CredentialBinding::verify_credential(
                    ln.credential(),
                    ln.signature_key().as_slice(),
                    self.group_tag,
                )?;
                if &endpoint != joiner {
                    return policy("Add subject differs from the signed intent");
                }
                let kp_ref = kp
                    .hash_ref(&crypto())
                    .map_err(|e| Violation::Policy(format!("KeyPackage ref: {e:?}")))?;
                let author = parent
                    .iter()
                    .find(|m| m.index.u32() == t.author_leaf)
                    .ok_or_else(|| Violation::Policy("author is not a parent member".into()))?;
                if &transcript.group_tag != self.group_tag
                    || &transcript.relay_key != self.relay_key
                    || transcript.incarnation != self.incarnation
                    || transcript.issuer_endpoint != t.author_endpoint
                    || transcript.issuer_mls_key != author.signature_key
                    || &transcript.joiner_endpoint != joiner
                    || transcript.key_package_ref != kp_ref.as_slice()
                {
                    return policy(
                        "joiner proof does not bind this group, issuer, relay and KeyPackage",
                    );
                }
                transcript
                    .verify(proof)
                    .map_err(|e| Violation::Signature(format!("joiner proof: {}", e.0)))?;
                if roster.iter().any(|(ep, _)| ep == joiner) {
                    return policy("endpoint is already a member (identity replacement)");
                }
                if roster
                    .iter()
                    .any(|(_, sk)| sk.as_slice() == ln.signature_key().as_slice())
                {
                    return policy("duplicate MLS signature key");
                }
                if self.revoked.contains(joiner) {
                    return policy("Add readmits a revoked endpoint");
                }
                roster.push((endpoint, ln.signature_key().as_slice().to_vec()));
            }
            (Proposal::Remove(rm), Op::Remove { subject, leaf }) => {
                if rm.removed().u32() != *leaf {
                    return policy("Remove leaf differs from the signed intent");
                }
                let m = parent
                    .iter()
                    .find(|m| m.index.u32() == *leaf)
                    .ok_or_else(|| Violation::Policy("Remove of a non-member".into()))?;
                if &self.endpoint_of(m)? != subject {
                    return policy("Remove subject differs from the signed intent");
                }
                roster.retain(|(ep, _)| ep != subject);
                if !revoked.contains(subject) {
                    revoked.push(*subject);
                }
            }
            (p, _) => {
                return policy(format!(
                    "unsupported or mismatched operation {:?}",
                    p.proposal_type()
                ));
            }
        }
        let path_leaf = match staged.update_path_leaf_node() {
            Some(l) => l,
            None => return policy("missing update path"),
        };
        let author = parent
            .iter()
            .find(|m| m.index.u32() == t.author_leaf)
            .ok_or_else(|| Violation::Policy("author is not a parent member".into()))?;
        if path_leaf.credential() != &author.credential
            || path_leaf.signature_key().as_slice() != author.signature_key.as_slice()
        {
            return policy("committer changed its pinned credential or signature key");
        }
        let gc = staged.group_context();
        let pc = self.group.public_group().group_context();
        if gc.group_id().as_slice() != self.group_id
            || gc.group_id() != pc.group_id()
            || gc.ciphersuite() != pc.ciphersuite()
            || gc.protocol_version() != pc.protocol_version()
            || gc.extensions() != pc.extensions()
            || gc.epoch().as_u64() != pc.epoch().as_u64() + 1
        {
            return policy("group context change");
        }
        roster.sort();
        revoked.sort();
        if staged.self_removed() {
            return Ok(Checked {
                roster,
                revoked,
                digest: None,
                self_removed: true,
            });
        }
        let digest = state_digest(gc, &roster, &revoked);
        Ok(Checked {
            roster,
            revoked,
            digest: Some(digest),
            self_removed: false,
        })
    }
}

// ------------------------------------------------- signed proposal vector

/// Byte span of the commit's `proposals` vector inside a TLS-encoded
/// `MLSMessage` carrying a member `PublicMessage` commit: (start of the
/// varint length prefix, start of the vector body, body length).
///
/// This is a narrow MassRelay cross-check, not an MLS parser. It walks only
/// the RFC 9420 framing fields that precede the vector (`version`,
/// `wire_format`, `group_id`, `epoch`, `sender`, `authenticated_data`,
/// `content_type`) and never interprets proposal bodies. OpenMLS 0.10.0-rc.1
/// exposes no public accessor for the original proposal vector (`CommitIn`
/// is crate-private); replace this with one when a reviewed API exists.
pub fn commit_proposal_span(msg: &[u8]) -> Result<(usize, usize, usize), String> {
    fn varint(b: &[u8], at: &mut usize) -> Result<usize, String> {
        let first = *b.get(*at).ok_or("truncated varint")?;
        let len = match first >> 6 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => return Err("invalid varint prefix".into()),
        };
        let raw = b.get(*at..*at + len).ok_or("truncated varint")?;
        let mut v = (raw[0] & 0x3f) as usize;
        for x in &raw[1..] {
            v = (v << 8) | *x as usize;
        }
        *at += len;
        Ok(v)
    }
    fn skip(b: &[u8], at: &mut usize, n: usize) -> Result<(), String> {
        if b.len() < *at + n {
            return Err("truncated framing".into());
        }
        *at += n;
        Ok(())
    }
    let mut at = 0usize;
    let head = msg.get(0..4).ok_or("truncated framing")?;
    if head != [0, 1, 0, 1] {
        return Err("expected an MLS 1.0 PublicMessage".into());
    }
    at += 4;
    let gid = varint(msg, &mut at)?;
    skip(msg, &mut at, gid)?;
    skip(msg, &mut at, 8)?; // epoch
    let sender_type = *msg.get(at).ok_or("truncated framing")?;
    at += 1;
    if sender_type != 1 {
        return Err("sender is not a member".into());
    }
    skip(msg, &mut at, 4)?; // leaf index
    let aad = varint(msg, &mut at)?;
    skip(msg, &mut at, aad)?;
    if *msg.get(at).ok_or("truncated framing")? != 3 {
        return Err("content is not a commit".into());
    }
    at += 1;
    let prefix = at;
    let len = varint(msg, &mut at)?;
    if msg.len() < at + len {
        return Err("truncated proposal vector".into());
    }
    Ok((prefix, at, len))
}

/// The signed proposal vector must be exactly one inline proposal whose
/// canonical encoding equals the proposal OpenMLS verified and staged.
pub fn check_single_inline_proposal(commit: &[u8], verified: &Proposal) -> Result<(), Violation> {
    use openmls::prelude::tls_codec::Serialize as _;
    let expected =
        openmls::messages::proposals::ProposalOrRef::Proposal(Box::new(verified.clone()))
            .tls_serialize_detached()
            .map_err(|e| Violation::Policy(format!("proposal encoding: {e:?}")))?;
    check_proposal_vector(commit, &expected)
}

/// The commit's proposal vector must be exactly `expected` (one encoded
/// `ProposalOrRef`), byte for byte.
pub fn check_proposal_vector(commit: &[u8], expected: &[u8]) -> Result<(), Violation> {
    let (_, body, len) = commit_proposal_span(commit)
        .map_err(|e| Violation::Policy(format!("commit framing: {e}")))?;
    if &commit[body..body + len] != expected {
        return policy("signed commit does not carry exactly one inline proposal");
    }
    Ok(())
}
