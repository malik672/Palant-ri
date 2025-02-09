use alloy_primitives::{B256, U64};

use crate::{find_field, hex_to_b256, hex_to_u64};

#[derive(Debug, Default, Clone)]
pub struct Updates {
    pub version: String,
    pub attested_header: Beacon,
    pub pubkeys: Vec<B256>,
    pub aggregate_pubkey: B256,
    pub next_sync_committee_branch: Vec<B256>,
    pub finalized_header: Beacon,
    pub finality_branch: Vec<B256>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: U64,
    pub code: Option<u16>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SyncAggregate {
    pub sync_committee_bits: U64,
    pub sync_committee_signature: B256,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Beacon {
    pub slot: U64,
    pub proposer_index: U64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

impl<'a> Updates {
    pub fn parse(input: &'a [u8]) -> Option<Self> {
        if memchr::memmem::find(input, b"\"code\":").is_some() {
            let code = find_field(input, b"\"code\":", b",")?;
            let code_str = std::str::from_utf8(&input[code.0..code.1]).ok()?;
            return Some(Self {
                code: Some(code_str.parse().ok()?),
                ..Default::default()
            });
        }

        let version = find_field(input, b"\"version\":\"", b"\"")?;

        let signature_key = find_field(input, b"\"signature_slot\":\"", b"\"")?;

        let finalized_header = find_field(input, b"\"finalized_header\":\"", b"}")?;
        let attested_header = find_field(input, b"\"attested_header\":\"", b"}")?;
        let sync_committee_bits = find_field(input, b"\"sync_committee_bits\":\"", b"\"")?;
        let sync_committee_signatures =
            find_field(input, b"\"sync_committee_signatures\":\"", b"\"")?;

        let finality_branch: Vec<B256> = Self::finality_branch(input)?
            .iter()
            .map(|&(start, end)| hex_to_b256(&input[start..end]))
            .collect();

        let next_sync_committee_branch: Vec<B256> = Self::next_sync_committee_branch(input)?
            .iter()
            .map(|&(start, end)| hex_to_b256(&input[start..end]))
            .collect();

        let pubkeys: Vec<B256> = Self::pubkeys(input)?
            .iter()
            .map(|&(start, end)| hex_to_b256(&input[start..end]))
            .collect();

        let slot_f = find_field(
            &input[finalized_header.0..finalized_header.1],
            b"\"slot\":\"",
            b"\"",
        )?;
        let proposer_index_f = find_field(
            &input[finalized_header.0..finalized_header.1],
            b"\"proposer_index\":\"",
            b"\"",
        )?;
        let parent_root_f = find_field(
            &input[finalized_header.0..finalized_header.1],
            b"\"parent_root\":\"",
            b"\"",
        )?;
        let state_root_f = find_field(
            &input[finalized_header.0..finalized_header.1],
            b"\"state_root\":\"",
            b"\"",
        )?;
        let body_root_f = find_field(
            &input[finalized_header.0..finalized_header.1],
            b"\"body_root\":\"",
            b"\"",
        )?;

        let beacon_f = Beacon {
            slot: hex_to_u64(&input[slot_f.0..slot_f.1]),
            proposer_index: hex_to_u64(&input[proposer_index_f.0..proposer_index_f.1]),
            parent_root: hex_to_b256(&input[parent_root_f.0..parent_root_f.1]),
            state_root: hex_to_b256(&input[state_root_f.0..state_root_f.1]),
            body_root: hex_to_b256(&input[body_root_f.0..body_root_f.1]),
        };

        let slot_a = find_field(
            &input[attested_header.0..attested_header.1],
            b"\"slot\":\"",
            b"\"",
        )?;
        let proposer_index_a = find_field(
            &input[attested_header.0..attested_header.1],
            b"\"proposer_index\":\"",
            b"\"",
        )?;
        let parent_root_a = find_field(
            &input[attested_header.0..attested_header.1],
            b"\"parent_root\":\"",
            b"\"",
        )?;
        let state_root_a = find_field(
            &input[attested_header.0..attested_header.1],
            b"\"state_root\":\"",
            b"\"",
        )?;
        let body_root_a = find_field(
            &input[attested_header.0..attested_header.1],
            b"\"body_root\":\"",
            b"\"",
        )?;
        let aggregate_pub_key = find_field(input, b"\"aggregate_pubkey\":\"", b"\"")?;

        let beacon_a = Beacon {
            slot: hex_to_u64(&input[slot_a.0..slot_a.1]),
            proposer_index: hex_to_u64(&input[proposer_index_a.0..proposer_index_a.1]),
            parent_root: hex_to_b256(&input[parent_root_a.0..parent_root_a.1]),
            state_root: hex_to_b256(&input[state_root_a.0..state_root_a.1]),
            body_root: hex_to_b256(&input[body_root_a.0..body_root_a.1]),
        };

        let sync_aggregate = SyncAggregate {
            sync_committee_bits: hex_to_u64(&input[sync_committee_bits.0..sync_committee_bits.1]),
            sync_committee_signature: hex_to_b256(
                &input[sync_committee_signatures.0..sync_committee_signatures.1],
            ),
        };

        Some(Updates {
            version: std::str::from_utf8(&input[version.0..version.1])
                .ok()?
                .to_string(),
            attested_header: beacon_a,
            finalized_header: beacon_f,
            finality_branch,
            sync_aggregate,
            signature_slot: hex_to_u64(&input[signature_key.0..signature_key.1]),
            pubkeys,
            aggregate_pubkey: hex_to_b256(&input[aggregate_pub_key.0..aggregate_pub_key.1]),
            next_sync_committee_branch,
            code: None,
        })
    }

    pub fn finality_branch(data: &[u8]) -> Option<Vec<(usize, usize)>> {
        let start = memchr::memmem::find(data, b"\"finality_branch\":[")?;
        let mut pos = start + b"\"finality_branch\":[".len();
        let mut result = Vec::new();

        while data[pos] != b']' {
            while data[pos] != b'"' && data[pos] != b']' {
                pos += 1;
            }
            if data[pos] == b']' {
                break;
            }
            pos += 1;
            let committee_start = pos;

            while data[pos] != b'"' {
                pos += 1;
            }
            result.push((committee_start, pos));
            pos += 1;
        }

        Some(result)
    }

    pub fn pubkeys(data: &[u8]) -> Option<Vec<(usize, usize)>> {
        let start = memchr::memmem::find(data, b"\"pubkeys\":[")?;
        let mut pos = start + b"\"pubkeys\":[".len();
        let mut result = Vec::new();

        while data[pos] != b']' {
            while data[pos] != b'"' && data[pos] != b']' {
                pos += 1;
            }
            if data[pos] == b']' {
                break;
            }
            pos += 1;
            let committee_start = pos;

            while data[pos] != b'"' {
                pos += 1;
            }
            result.push((committee_start, pos));
            pos += 1;
        }

        Some(result)
    }

    pub fn next_sync_committee_branch(data: &[u8]) -> Option<Vec<(usize, usize)>> {
        let start = memchr::memmem::find(data, b"\"next_sync_committee_branch\":[")?;
        let mut pos = start + b"\"next_sync_committee_branch\":[".len();
        let mut result = Vec::new();

        while data[pos] != b']' {
            while data[pos] != b'"' && data[pos] != b']' {
                pos += 1;
            }
            if data[pos] == b']' {
                break;
            }
            pos += 1;
            let committee_start = pos;

            while data[pos] != b'"' {
                pos += 1;
            }
            result.push((committee_start, pos));
            pos += 1;
        }

        Some(result)
    }
}
