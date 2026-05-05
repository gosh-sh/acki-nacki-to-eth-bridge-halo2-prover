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

    /// Fetch bkSetUpdates with their attestations.
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
