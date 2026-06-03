use anyhow::{bail, Context};
use serde_json::{json, Value};

/// Lightweight GraphQL client for the acki-nacki node.
pub struct GqlClient {
    http: reqwest::Client,
    url: String,
}

pub fn create_client(endpoint: &str) -> anyhow::Result<GqlClient> {
    let url = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        if endpoint.trim_end_matches('/').ends_with("/graphql") {
            endpoint.to_string()
        } else {
            format!("{}/graphql", endpoint.trim_end_matches('/'))
        }
    } else {
        format!("http://{}/graphql", endpoint)
    };
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to create HTTP client")?;
    Ok(GqlClient { http, url })
}

impl GqlClient {
    pub async fn query(&self, query: &str) -> anyhow::Result<Value> {
        let resp = self
            .http
            .post(&self.url)
            .json(&json!({ "query": query }))
            .send()
            .await
            .context("GraphQL request failed")?;
        let body: Value = resp.json().await.context("failed to decode GraphQL response")?;
        if let Some(errors) = body.get("errors") {
            bail!("GraphQL error: {}", errors);
        }
        body.get("data")
            .cloned()
            .ok_or_else(|| anyhow::format_err!("no 'data' field in GraphQL response"))
    }

    /// Fetch the latest N blocks (hash + seq_no).
    pub async fn query_latest_blocks(&self, count: u32) -> anyhow::Result<Vec<(String, u64)>> {
        let q = format!(
            r#"{{ blockchain {{ blocks(last: {count}) {{ edges {{ node {{ hash seq_no }} }} }} }} }}"#
        );
        let data = self.query(&q).await?;
        let edges = data
            .pointer("/blockchain/blocks/edges")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut blocks = Vec::new();
        for edge in &edges {
            let node = edge.get("node").unwrap_or(&Value::Null);
            let hash = node.get("hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let seq_no = node.get("seq_no").and_then(|v| v.as_u64()).unwrap_or(0);
            blocks.push((hash, seq_no));
        }
        Ok(blocks)
    }

    /// Fetch the hash and BOC of a block by seq_no.
    ///
    /// Uses cursor-based pagination: queries blocks from the end, walking backwards
    /// until we find the target seq_no. Returns (hash, boc_bytes).
    pub async fn query_block_boc_by_seq_no(&self, seq_no: u64) -> anyhow::Result<(String, Vec<u8>)> {
        // Strategy: query a window of recent blocks and find the one with matching seq_no.
        // If not found, try larger windows or use the blockByHeight endpoint.
        let tid = "00000000000000000000000000000000000000000000000000000000000000000000";
        let q = format!(
            r#"{{ blockchain {{ blockByHeight(thread_id: "{tid}", height: {seq_no}) {{ hash boc }} }} }}"#
        );
        let data = self.query(&q).await?;
        let block = data
            .pointer("/blockchain/blockByHeight")
            .ok_or_else(|| anyhow::format_err!("blockByHeight returned null for seq_no={}", seq_no))?;
        if block.is_null() {
            anyhow::bail!("block at seq_no={} not found", seq_no);
        }
        let hash = block.get("hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let boc_str = block.get("boc").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::format_err!("no boc for block at seq_no={}", seq_no))?;
        use base64::Engine;
        let boc_bytes = base64::engine::general_purpose::STANDARD
            .decode(boc_str)
            .context("failed to base64-decode BOC")?;
        Ok((hash, boc_bytes))
    }

    /// Fetch a block's raw BOC (base64) by hash.
    pub async fn query_block_boc(&self, hash: &str) -> anyhow::Result<Vec<u8>> {
        let q = format!(
            r#"{{ blockchain {{ block(hash: "{hash}") {{ boc }} }} }}"#
        );
        let data = self.query(&q).await?;
        let boc_str = data
            .pointer("/blockchain/block/boc")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::format_err!("block {} not found or no boc", hash))?;
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(boc_str)
            .context("failed to base64-decode BOC")
    }

    /// Fetch bkSetUpdates (light — no attestation subfields).
    /// `first_or_last`: true = first N (oldest), false = last N (newest).
    pub async fn query_bk_set_updates_light(
        &self,
        count: u32,
        first: bool,
    ) -> anyhow::Result<Vec<BkSetUpdateWithAttestations>> {
        let pagination = if first {
            format!("first: {count}")
        } else {
            format!("last: {count}")
        };
        let q = format!(
            r#"{{
              blockchain {{
                bkSetUpdates({pagination}) {{
                  edges {{
                    node {{
                      block_id
                      bk_set_update
                      height
                    }}
                  }}
                }}
              }}
            }}"#
        );
        let data = self.query(&q).await?;
        let edges = data
            .pointer("/blockchain/bkSetUpdates/edges")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut updates = Vec::new();
        for edge in &edges {
            if let Some(node) = edge.get("node") {
                let block_id = node.get("block_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let bk_set_update_hex = node.get("bk_set_update").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let height = node.get("height").and_then(|v| v.as_u64());
                updates.push(BkSetUpdateWithAttestations {
                    block_id,
                    bk_set_update_hex,
                    height,
                    attestations: Vec::new(), // no attestations in light query
                });
            }
        }
        Ok(updates)
    }

    /// Fetch the last N bkSetUpdates (most recent).
    pub async fn query_bk_set_updates_last(
        &self,
        last: u32,
    ) -> anyhow::Result<Vec<BkSetUpdateWithAttestations>> {
        let q = format!(
            r#"{{
              blockchain {{
                bkSetUpdates(last: {last}) {{
                  edges {{
                    node {{
                      block_id
                      bk_set_update
                      height
                      attestations {{
                        block_id
                        parent_block_id
                        target_type
                        envelope_hash
                        aggregated_signature
                        signature_occurrences
                      }}
                    }}
                  }}
                }}
              }}
            }}"#
        );
        let data = self.query(&q).await?;
        let edges = data
            .pointer("/blockchain/bkSetUpdates/edges")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut updates = Vec::new();
        for edge in &edges {
            if let Some(node) = edge.get("node") {
                updates.push(BkSetUpdateWithAttestations::from_json(node)?);
            }
        }
        Ok(updates)
    }

    /// Fetch block metadata by seq_no: hash, envelope_hash, seq_no.
    /// Used for computing block leaf hashes in chain proof construction.
    pub async fn query_block_metadata(
        &self,
        seq_no: u64,
    ) -> anyhow::Result<BlockMetadata> {
        let tid = "00000000000000000000000000000000000000000000000000000000000000000000";
        let q = format!(
            r#"{{ blockchain {{ blockByHeight(thread_id: "{tid}", height: {seq_no}) {{ hash envelope_hash seq_no }} }} }}"#
        );
        let data = self.query(&q).await?;
        let block = data
            .pointer("/blockchain/blockByHeight")
            .ok_or_else(|| anyhow::format_err!("blockByHeight returned null for seq_no={}", seq_no))?;
        if block.is_null() {
            anyhow::bail!("block at seq_no={} not found", seq_no);
        }
        Ok(BlockMetadata {
            hash: block.get("hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            envelope_hash: block.get("envelope_hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            seq_no: block.get("seq_no").and_then(|v| v.as_u64()).unwrap_or(0),
        })
    }

    /// Fetch metadata for a range of blocks [from_seq..=to_seq].
    pub async fn query_blocks_metadata_range(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> anyhow::Result<Vec<BlockMetadata>> {
        let mut results = Vec::new();
        for seq in from_seq..=to_seq {
            match self.query_block_metadata(seq).await {
                Ok(meta) => results.push(meta),
                Err(e) => {
                    tracing::warn!("failed to fetch block metadata for seq={}: {}", seq, e);
                    // Still push a placeholder to keep alignment
                    results.push(BlockMetadata {
                        hash: String::new(),
                        envelope_hash: String::new(),
                        seq_no: seq,
                    });
                }
            }
        }
        Ok(results)
    }

    /// Fetch the first N bkSetUpdates (oldest first).
    pub async fn query_bk_set_updates(
        &self,
        first: u32,
    ) -> anyhow::Result<Vec<BkSetUpdateWithAttestations>> {
        let q = format!(
            r#"{{
              blockchain {{
                bkSetUpdates(first: {first}) {{
                  edges {{
                    node {{
                      block_id
                      bk_set_update
                      height
                      attestations {{
                        block_id
                        parent_block_id
                        target_type
                        envelope_hash
                        aggregated_signature
                        signature_occurrences
                      }}
                    }}
                  }}
                }}
              }}
            }}"#
        );
        let data = self.query(&q).await?;
        let edges = data
            .pointer("/blockchain/bkSetUpdates/edges")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut updates = Vec::new();
        for edge in &edges {
            if let Some(node) = edge.get("node") {
                updates.push(BkSetUpdateWithAttestations::from_json(node)?);
            }
        }
        Ok(updates)
    }
}

/// Block metadata used for computing block leaf hashes.
#[derive(Debug, Clone)]
pub struct BlockMetadata {
    /// TVM block representation hash (legacy) as hex string.
    pub hash: String,
    /// Envelope hash (SHA-256 of BLS envelope) as hex string.
    pub envelope_hash: String,
    /// Block sequence number / height.
    pub seq_no: u64,
}

#[derive(Debug, Clone)]
pub struct GqlAttestation {
    pub block_id: String,
    pub parent_block_id: String,
    pub target_type: u8,
    pub envelope_hash: String,
    pub aggregated_signature: String,
    pub signature_occurrences: std::collections::HashMap<u16, u16>,
}

impl GqlAttestation {
    pub fn from_json(v: &Value) -> anyhow::Result<Self> {
        let block_id = v
            .get("block_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let parent_block_id = v
            .get("parent_block_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let target_type = match v
            .get("target_type")
            .and_then(|v| v.as_str())
            .unwrap_or("PRIMARY")
        {
            "PRIMARY" | "Primary" => 0,
            "FALLBACK" | "Fallback" => 1,
            other => bail!("unknown target_type: {}", other),
        };
        let envelope_hash = v
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let aggregated_signature = v
            .get("aggregated_signature")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let sig_occ_json = v.get("signature_occurrences").cloned().unwrap_or(Value::Null);
        let mut signature_occurrences = std::collections::HashMap::new();
        if let Some(obj) = sig_occ_json.as_object() {
            for (k, v) in obj {
                let signer_idx: u16 = k.parse().context("invalid signer index")?;
                let count = v.as_u64().unwrap_or(0) as u16;
                signature_occurrences.insert(signer_idx, count);
            }
        }
        Ok(Self {
            block_id,
            parent_block_id,
            target_type,
            envelope_hash,
            aggregated_signature,
            signature_occurrences,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BkSetUpdateWithAttestations {
    pub block_id: String,
    pub bk_set_update_hex: String,
    pub height: Option<u64>,
    pub attestations: Vec<GqlAttestation>,
}

impl BkSetUpdateWithAttestations {
    pub fn from_json(v: &Value) -> anyhow::Result<Self> {
        let block_id = v
            .get("block_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let bk_set_update_hex = v
            .get("bk_set_update")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let height = v.get("height").and_then(|v| v.as_u64());
        let att_json = v
            .get("attestations")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut attestations = Vec::new();
        for a in &att_json {
            attestations.push(GqlAttestation::from_json(a)?);
        }
        Ok(Self {
            block_id,
            bk_set_update_hex,
            height,
            attestations,
        })
    }
}

use std::collections::BTreeMap;
use crate::poseidon_dense::{compute_block_leaf_hash, LayerNumber};
use crate::types::{AccountRouting, ThreadIdentifier};

/// GraphQL-fetched proof block — replaces `Envelope<AckiNackiBlock>` as the
/// authoritative source of per-block proof data. Mirrors
/// `acki-nacki/helpers/proof_helper/src/blockchain.rs::GqlProofBlock`.
#[derive(Clone, Debug)]
pub struct GqlProofBlock {
    pub id: String,
    pub block_id: [u8; 32],
    pub thread_id: ThreadIdentifier,
    pub height: u64,
    pub envelope_hash: [u8; 32],
    pub tracked_ext_out_messages_root: [u8; 32],
    pub tracked_ext_out_messages: BTreeMap<AccountRouting, Vec<[u8; 32]>>,
    pub history_proofs: BTreeMap<LayerNumber, [u8; 32]>,
    /// 8-leaf SHA-256 block-id Merkle leaves. May be absent on very old blocks.
    pub block_merkle_tree_leaves: Option<[[u8; 32]; 8]>,
}

impl GqlProofBlock {
    pub fn block_leaf_hash(&self) -> [u8; 32] {
        compute_block_leaf_hash(
            &self.block_id,
            &self.envelope_hash,
            &self.tracked_ext_out_messages_root,
        )
    }
}

/// Default thread_id used by the single-thread testbed.
pub const DEFAULT_THREAD_ID_HEX: &str =
    "00000000000000000000000000000000000000000000000000000000000000000000";

const PROOF_BLOCK_FRAGMENT: &str = r#"
  fragment ProofBlockFields on Block {
    id
    block_id
    thread_id
    height
    envelope_hash
    tracked_ext_out_messages_root
    tracked_ext_out_message_hashes {
      routing
      message_hashes
    }
    history_proofs {
      layer
      root_hash
    }
    block_merkle_tree_leaves
  }
"#;

impl GqlClient {
    /// Fetch a `GqlProofBlock` by (thread_id, height). thread_id_hex should be
    /// the 68-hex-char form the node emits (34 bytes).
    pub async fn query_block_by_height(
        &self,
        thread_id_hex: &str,
        height: u64,
    ) -> anyhow::Result<GqlProofBlock> {
        let q = format!(
            r#"{{
              blockchain {{
                blockByHeight(thread_id: "{thread_id_hex}", height: {height}) {{
                  id block_id thread_id height envelope_hash
                  tracked_ext_out_messages_root
                  tracked_ext_out_message_hashes {{ routing message_hashes }}
                  history_proofs {{ layer root_hash }}
                  block_merkle_tree_leaves
                }}
              }}
            }}"#,
        );
        let _ = PROOF_BLOCK_FRAGMENT; // keep fragment as documentation
        let data = self.query(&q).await?;
        let block = data
            .pointer("/blockchain/blockByHeight")
            .ok_or_else(|| anyhow::format_err!("blockByHeight returned no field for height={height}"))?;
        if block.is_null() {
            anyhow::bail!("block at thread_id={thread_id_hex} height={height} not found");
        }
        parse_proof_block(block)
    }

    /// Fetch a `GqlProofBlock` on the default single-thread testbed by seq_no.
    pub async fn query_proof_block_by_seqno(&self, seqno: u64) -> anyhow::Result<GqlProofBlock> {
        self.query_block_by_height(DEFAULT_THREAD_ID_HEX, seqno).await
    }
}

fn parse_proof_block(value: &serde_json::Value) -> anyhow::Result<GqlProofBlock> {
    use std::str::FromStr;
    let id = required_string(value, "id")?.to_string();
    let block_id = decode_hash32(required_string(value, "block_id")?).context("block_id")?;
    let thread_id =
        ThreadIdentifier::try_from(required_string(value, "thread_id")?.to_string())
            .context("thread_id")?;
    let height = parse_u64_field(value, "height")?;
    let envelope_hash =
        decode_hash32(required_string(value, "envelope_hash")?).context("envelope_hash")?;
    let tracked_ext_out_messages_root =
        decode_hash32(required_string(value, "tracked_ext_out_messages_root")?)
            .context("tracked_ext_out_messages_root")?;

    // tracked_ext_out_message_hashes -> BTreeMap<AccountRouting, Vec<[u8;32]>>
    let mut tracked_ext_out_messages: BTreeMap<AccountRouting, Vec<[u8; 32]>> = BTreeMap::new();
    if let Some(arr) = value.get("tracked_ext_out_message_hashes").and_then(|v| v.as_array()) {
        for entry in arr {
            let routing = AccountRouting::from_str(required_string(entry, "routing")?)
                .context("tracked_ext_out_messages routing")?;
            let mh = entry
                .get("message_hashes")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow::format_err!("message_hashes is not an array"))?;
            let mut hashes = Vec::with_capacity(mh.len());
            for h in mh {
                let h = h
                    .as_str()
                    .ok_or_else(|| anyhow::format_err!("message hash is not a string"))?;
                hashes.push(decode_hash32(h).context("tracked message hash")?);
            }
            tracked_ext_out_messages.insert(routing, hashes);
        }
    }

    // history_proofs -> BTreeMap<u8, [u8;32]>
    let mut history_proofs: BTreeMap<LayerNumber, [u8; 32]> = BTreeMap::new();
    if let Some(arr) = value.get("history_proofs").and_then(|v| v.as_array()) {
        for entry in arr {
            let layer = parse_u64_field(entry, "layer")?;
            anyhow::ensure!(layer <= u8::MAX as u64, "history proof layer out of range");
            let root_hash =
                decode_hash32(required_string(entry, "root_hash")?).context("history proof root_hash")?;
            history_proofs.insert(layer as u8, root_hash);
        }
    }

    // block_merkle_tree_leaves -> Option<[[u8;32]; 8]>
    let block_merkle_tree_leaves = match value.get("block_merkle_tree_leaves") {
        Some(serde_json::Value::Array(items)) => {
            anyhow::ensure!(items.len() == 8, "block_merkle_tree_leaves must have 8 entries");
            let mut out = [[0u8; 32]; 8];
            for (i, item) in items.iter().enumerate() {
                let s = item.as_str().ok_or_else(|| {
                    anyhow::format_err!("block_merkle_tree_leaves[{i}] is not a string")
                })?;
                out[i] = decode_hash32(s).with_context(|| format!("block_merkle_tree_leaves[{i}]"))?;
            }
            Some(out)
        }
        _ => None,
    };

    Ok(GqlProofBlock {
        id,
        block_id,
        thread_id,
        height,
        envelope_hash,
        tracked_ext_out_messages_root,
        tracked_ext_out_messages,
        history_proofs,
        block_merkle_tree_leaves,
    })
}

fn required_string<'a>(v: &'a serde_json::Value, field: &str) -> anyhow::Result<&'a str> {
    v.get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::format_err!("missing or non-string field `{field}`"))
}

fn parse_u64_field(v: &serde_json::Value, field: &str) -> anyhow::Result<u64> {
    let val = v.get(field).ok_or_else(|| anyhow::format_err!("missing field `{field}`"))?;
    if let Some(n) = val.as_u64() {
        return Ok(n);
    }
    if let Some(n) = val.as_i64() {
        return u64::try_from(n).with_context(|| format!("{field} is negative"));
    }
    if let Some(n) = val.as_f64() {
        anyhow::ensure!(n.is_finite() && n >= 0.0 && n.fract() == 0.0, "{field} not an integer");
        return Ok(n as u64);
    }
    anyhow::bail!("{field} is not a number")
}

fn decode_hash32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| anyhow::format_err!("invalid hex: {e}"))?;
    anyhow::ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
