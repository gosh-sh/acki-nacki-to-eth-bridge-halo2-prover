//! Test that our Poseidon tree reconstruction matches the node's actual layer roots.

use bridge_prover_lib::chain_proof_builder::{build_tree_and_proof, compute_block_leaf_hash, pad_leaves_to_power_of_2};

/// Extract real block_ids from attestations in subsequent blocks,
/// then verify tree reconstruction.
/// Requires local Docker node running.
#[test]
fn test_extract_real_block_ids_and_reconstruct() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let gql = bridge_prover_lib::gql_client::create_client("http://localhost/graphql").unwrap();

    let ext_msg_root = [0u8; 32];

    // For each block, the attestation referencing it is in the NEXT block's BOC.
    // Extract real block_id (Merkle root) from the attestation.
    println!("Extracting real block_ids from attestations...\n");

    let mut real_block_ids: std::collections::HashMap<u64, [u8; 32]> = std::collections::HashMap::new();
    for target_seq in 1u64..=8 {
        let att_result = rt.block_on(async {
            bridge_prover_lib::attestation_fetcher::fetch_attestation_for_block(&gql, target_seq as u32).await
        });
        match att_result {
            Ok(att) => {
                let gql_hash = rt.block_on(async {
                    gql.query_block_metadata(target_seq).await.unwrap().hash
                });
                println!("Block {}: real_block_id={} (from attestation)", target_seq, hex::encode(att.block_id));
                println!("         gql_hash=     {} (TVM repr_hash)", gql_hash);
                println!("         same: {}", hex::encode(att.block_id) == gql_hash);
                real_block_ids.insert(target_seq, att.block_id);
            }
            Err(e) => {
                println!("Block {}: no attestation found ({})", target_seq, e);
            }
        }
    }
    println!();

    // Now try to reconstruct the layer 1 tree for block 4.
    let l1_at_4 = {
        // Fetch from history_proofs
        let data = rt.block_on(async { gql.query_block_data_field(4).await.unwrap() });
        let bd = bridge_prover_lib::block_data_parser::parse_block_data(&data).unwrap();
        *bd.history_proofs.get(&1).expect("block 4 should have L1")
    };
    println!("L1 root at block 4 (expected tree root): {}", hex::encode(l1_at_4));

    // Build block leaves using REAL block_ids from attestations
    if real_block_ids.len() >= 4 {
        let mut data_leaves = Vec::new();
        for seq in 1u64..=4 {
            let block_id = real_block_ids.get(&seq).expect(&format!("need block_id for block {}", seq));
            let envelope_hash = rt.block_on(async {
                let meta = gql.query_block_metadata(seq).await.unwrap();
                hex_to_bytes(&meta.envelope_hash)
            });
            let leaf = compute_block_leaf_hash(block_id, &envelope_hash, &ext_msg_root);
            println!("block {} leaf (real_id): {}", seq, hex::encode(leaf));
            data_leaves.push(leaf);
        }

        // Tree: [higher=0, prev_same=0, leaf1, leaf2, leaf3, leaf4, pad, pad]
        let mut leaves = vec![[0u8; 32], [0u8; 32]];
        leaves.extend_from_slice(&data_leaves);
        pad_leaves_to_power_of_2(&mut leaves);

        let (root, _) = build_tree_and_proof(&leaves, 1);
        println!("\ncomputed root (real block_ids): {}", hex::encode(root));
        println!("expected root:                  {}", hex::encode(l1_at_4));

        if root == l1_at_4 {
            println!("MATCH with real block_ids!");
        } else {
            // Try newest-first
            let mut nf: Vec<_> = data_leaves.iter().rev().cloned().collect();
            let mut leaves_nf = vec![[0u8; 32], [0u8; 32]];
            leaves_nf.extend_from_slice(&nf);
            pad_leaves_to_power_of_2(&mut leaves_nf);
            let (root_nf, _) = build_tree_and_proof(&leaves_nf, 1);
            println!("newest-first root:              {}", hex::encode(root_nf));
            if root_nf == l1_at_4 {
                println!("MATCH with newest-first ordering!");
            } else {
                panic!("Neither ordering matches with real block_ids");
            }
        }
    } else {
        println!("Not enough block_ids extracted, skipping tree test");
    }
}

/// Test tree reconstruction for block 4 (first key block).
/// Block 4 has higher_root=0, prev_same_root=0 — simplifies debugging.
///
/// IMPORTANT: GraphQL `hash` field = TVM block root hash (repr_hash),
/// NOT the Acki Nacki block_id (8-leaf Merkle root).
/// The node's compute_block_leaf_hash uses the REAL block_id (Merkle root).
/// To get it, we must compute it from the block's `data` field.
///
/// This test requires the local Docker node to be running.
#[test]
fn test_layer1_tree_block_4() {
    // L1 root at block 4 (expected, from node's history_proofs):
    let expected_root = hex_to_bytes("10e45ca22ee421e19ab0fdf9ae23bac122ad5af7965b72223e5d062e507d5d0a");

    // For each block 1-4, compute the REAL block_id from its data field,
    // then use it in compute_block_leaf_hash.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let gql = bridge_prover_lib::gql_client::create_client("http://localhost/graphql").unwrap();

    let ext_msg_root = [0u8; 32];

    let mut data_leaves = Vec::new();
    for seq in 1u64..=4 {
        // Compute REAL block_id from data field.
        let real_block_id = rt.block_on(async {
            compute_real_block_id(&gql, seq).await.unwrap()
        });

        // Get envelope_hash from metadata (this IS correct in GraphQL).
        let meta = rt.block_on(async {
            gql.query_block_metadata(seq).await.unwrap()
        });
        let envelope_hash = hex_to_bytes(&meta.envelope_hash);

        let leaf = compute_block_leaf_hash(&real_block_id, &envelope_hash, &ext_msg_root);
        println!("block {}: real_block_id={}, leaf={}", seq, hex::encode(real_block_id), hex::encode(leaf));
        data_leaves.push(leaf);
    }

    // Block 4 is first key block: higher_root=0, prev_same_root=0.
    let mut leaves = vec![[0u8; 32], [0u8; 32]]; // [higher=0, prev_same=0]
    leaves.extend_from_slice(&data_leaves);
    pad_leaves_to_power_of_2(&mut leaves);

    let (root_of, _) = build_tree_and_proof(&leaves, 1);
    println!("oldest-first root: {}", hex::encode(root_of));

    // Also try newest-first
    let mut leaves_nf = vec![[0u8; 32], [0u8; 32]];
    let rev: Vec<_> = data_leaves.iter().rev().cloned().collect();
    leaves_nf.extend_from_slice(&rev);
    pad_leaves_to_power_of_2(&mut leaves_nf);
    let (root_nf, _) = build_tree_and_proof(&leaves_nf, 1);
    println!("newest-first root: {}", hex::encode(root_nf));
    println!("expected root:     {}", hex::encode(expected_root));

    if root_of == expected_root {
        println!("MATCH: oldest-first!");
    } else if root_nf == expected_root {
        println!("MATCH: newest-first!");
    } else {
        // Debug: print all leaves
        println!("\nLeaves (oldest-first):");
        for (i, l) in leaves.iter().enumerate() {
            println!("  [{}]: {}", i, hex::encode(l));
        }
        panic!(
            "Neither ordering matches.\n  oldest={}\n  newest={}\n  expected={}",
            hex::encode(root_of), hex::encode(root_nf), hex::encode(expected_root),
        );
    }
}

/// Compute the REAL Acki Nacki block_id (8-leaf SHA-256 Merkle root)
/// from a block's `data` field.
async fn compute_real_block_id(
    gql: &bridge_prover_lib::gql_client::GqlClient,
    seq: u64,
) -> anyhow::Result<[u8; 32]> {
    use bridge_prover_lib::block_data_parser;
    use bridge_prover_lib::block_id_tree;
    use sha2::{Digest, Sha256};

    let data_bytes = gql.query_block_data_field(seq).await?;
    let bd = block_data_parser::parse_block_data(&data_bytes)?;

    let num_layers = bd.history_proofs.len();
    let mut root_hashes = Vec::with_capacity(10);
    for i in 1..=10u8 {
        root_hashes.push(bd.history_proofs.get(&i).copied().unwrap_or([0u8; 32]));
    }
    let preimage = block_id_tree::build_layer_hashes_preimage(num_layers, &root_hashes);

    let bk_old = bd.old_bk_set_hash.unwrap_or([0u8; 32]);
    let bk_new = bd.new_bk_set_hash.unwrap_or([0u8; 32]);
    let tvm_repr_hash: [u8; 32] = Sha256::digest(&bd.tvm_block_boc).into();

    let tree = block_id_tree::compute_block_id_tree(
        &preimage,
        &bd.common_section_bytes,
        &bk_old,
        &bk_new,
        &tvm_repr_hash,
        &bd.durable_state_bytes,
        bd.tx_cnt,
    );
    Ok(tree.block_id())
}

/// Definitive test: does bridge_poseidon::poseidon_hash_bytes match
/// gosh_dense_balanced_tree's native Poseidon for the SAME Fr inputs?
/// This isolates whether the two crates produce different outputs.
#[test]
fn test_poseidon_cross_crate_consistency() {
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;

    // Test with 96-byte input (block leaf hash: 4 chunks of 31 bytes)
    let input = {
        let mut buf = [0u8; 96];
        buf[0] = 0x42; buf[31] = 0x13; buf[63] = 0x07; buf[95] = 0x01;
        buf
    };

    // Method 1: bridge_poseidon::poseidon_hash_bytes (used by compute_block_leaf_hash)
    let result_bridge = bridge_poseidon::poseidon_hash_bytes(&input);
    println!("bridge_poseidon result:    {}", hex::encode(result_bridge));

    // Method 2: manual chunking + gosh_dense_balanced_tree::poseidon_hash_native
    // (this is what the tree combine uses internally)
    let chunks: Vec<Fr> = input
        .chunks(31)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[..chunk.len()].copy_from_slice(chunk);
            Fr::from_repr(buf).unwrap()
        })
        .collect();
    println!("num chunks: {}", chunks.len()); // should be 4

    let result_dense = gosh_dense_balanced_tree::fr_to_bytes(
        gosh_dense_balanced_tree::poseidon_hash_native(&chunks)
    );
    println!("gosh_dense_tree result:    {}", hex::encode(result_dense));

    // Method 3: bridge_poseidon::poseidon_hash_fr (Fr-level API)
    let result_fr = bridge_poseidon::poseidon_hash_fr_to_bytes(&chunks);
    println!("bridge_poseidon_fr result: {}", hex::encode(result_fr));

    assert_eq!(result_bridge, result_dense,
        "bridge_poseidon vs gosh_dense_tree MISMATCH for 96 bytes");
    assert_eq!(result_bridge, result_fr,
        "bridge_poseidon bytes vs fr MISMATCH");
    println!("All 3 methods agree!");
}

/// Test: does the tree COMBINE function match between our build_tree_and_proof
/// and what bridge_poseidon::poseidon_hash_bytes would produce?
#[test]
fn test_tree_combine_matches_poseidon_bytes() {
    let left = hex_to_bytes("1122334455667788990011223344556677889900112233445566778899001122");
    let right = hex_to_bytes("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");

    // Method 1: build_tree_and_proof (uses preprocess_dense_proof + compute_root_native)
    let (root, _) = build_tree_and_proof(&[left, right], 0);
    println!("build_tree_and_proof: {}", hex::encode(root));

    // Method 2: bridge_poseidon::poseidon_hash_bytes on concatenated 64 bytes
    let mut concat = [0u8; 64];
    concat[..32].copy_from_slice(&left);
    concat[32..].copy_from_slice(&right);
    let result_bytes = bridge_poseidon::poseidon_hash_bytes(&concat);
    println!("poseidon_hash_bytes:  {}", hex::encode(result_bytes));

    assert_eq!(root, result_bytes,
        "Tree combine vs poseidon_hash_bytes MISMATCH!\n  tree:    {}\n  poseidon: {}",
        hex::encode(root), hex::encode(result_bytes));
    println!("Tree combine and poseidon_hash_bytes AGREE!");
}

/// LIVE TEST: Reconstruct layer 1 tree for block 8 using block_identifier from GQL.
/// Requires local Docker node with block_identifier field.
#[test]
fn test_live_layer1_tree_with_block_identifier() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let gql = bridge_prover_lib::gql_client::create_client("http://localhost/graphql").unwrap();

    // Get L1 root at block 4 (prev_same) and L1 root at block 8 (expected tree root)
    let l1_4 = rt.block_on(async {
        bridge_prover_lib::real_chain_builder::fetch_layer_root_pub(&gql, 4, 1).await.unwrap()
    });
    let l1_8 = rt.block_on(async {
        bridge_prover_lib::real_chain_builder::fetch_layer_root_pub(&gql, 8, 1).await.unwrap()
    });
    println!("L1@4 (prev_same): {}", hex::encode(l1_4));
    println!("L1@8 (expected):  {}", hex::encode(l1_8));

    let ext_msg_root = [0u8; 32];

    // Build block leaves for blocks 5-8 using block_identifier and envelope_hash
    let mut data_leaves = Vec::new();
    for seq in 5u64..=8 {
        let meta = rt.block_on(async { gql.query_block_metadata(seq).await.unwrap() });
        let block_id_hex = meta.block_identifier.as_deref().unwrap_or(&meta.hash);
        let block_id = hex_to_bytes(block_id_hex);
        let envelope_hash = hex_to_bytes(&meta.envelope_hash);
        let leaf = compute_block_leaf_hash(&block_id, &envelope_hash, &ext_msg_root);
        println!("block {}: id={} eh={} leaf={}", seq,
            &block_id_hex[..16], &meta.envelope_hash[..16], hex::encode(leaf));
        data_leaves.push(leaf);
    }

    // Higher root = L2@8 (or zero if no L2)
    let higher_root = rt.block_on(async {
        bridge_prover_lib::real_chain_builder::fetch_layer_root_pub(&gql, 8, 2).await.unwrap_or([0u8; 32])
    });
    println!("higher_root (L2@8): {}", hex::encode(higher_root));

    // Tree: [higher, prev_same=L1@4, block5, block6, block7, block8, 0, 0]
    let mut leaves = vec![higher_root, l1_4];
    leaves.extend_from_slice(&data_leaves);
    pad_leaves_to_power_of_2(&mut leaves);

    let (root, _) = build_tree_and_proof(&leaves, 1);
    println!("\ncomputed root: {}", hex::encode(root));
    println!("expected root: {}", hex::encode(l1_8));
    assert_eq!(root, l1_8, "Tree root mismatch!");
    println!("MATCH! Layer 1 tree reconstruction works with block_identifier!");
}

/// Test basic Poseidon hash consistency: known input → known output.
/// This isolates whether bridge_poseidon::poseidon_hash_bytes is the issue.
#[test]
fn test_poseidon_basic() {
    // Hash all-zero 64 bytes (tree combine of two zero leaves)
    let zero64 = [0u8; 64];
    let r = bridge_poseidon::poseidon_hash_bytes(&zero64);
    println!("Poseidon([0;64]) = {}", hex::encode(r));

    // Hash all-zero 96 bytes (block leaf hash of zero inputs)
    let zero96 = [0u8; 96];
    let r2 = bridge_poseidon::poseidon_hash_bytes(&zero96);
    println!("Poseidon([0;96]) = {}", hex::encode(r2));

    // Hash via compute_block_leaf_hash
    let z32 = [0u8; 32];
    let r3 = compute_block_leaf_hash(&z32, &z32, &z32);
    println!("compute_block_leaf_hash([0;32],[0;32],[0;32]) = {}", hex::encode(r3));
    assert_eq!(r2, r3, "poseidon_hash_bytes and compute_block_leaf_hash should agree");

    // Also check dense tree combine
    use gosh_dense_balanced_tree::{preprocess_dense_proof, compute_root_native, fr_to_bytes};
    let proof = preprocess_dense_proof(z32, &[z32], 0);
    let root_fr = compute_root_native(&proof);
    let root_bytes = fr_to_bytes(root_fr);
    println!("dense_combine([0;32],[0;32]) = {}", hex::encode(root_bytes));
    assert_eq!(r, root_bytes, "bridge_poseidon and gosh-dense-balanced-tree should agree for tree combine");
}

#[test]
fn test_layer1_tree_reconstruction_block_8() {
    // Data from local Docker node (HISTORY_WINDOW_SIZE=4):
    // L1 root at block 4 (prev_same_layer_root for block 8):
    let l1_at_4 = hex_to_bytes("10e45ca22ee421e19ab0fdf9ae23bac122ad5af7965b72223e5d062e507d5d0a");
    // L1 root at block 8 (expected tree root):
    let expected_root = hex_to_bytes("f938754ebce625842175290662e0d200b07c328fdd92ca108fe2dd77b0fb6c08");

    // Block metadata (hash = block_id, envelope_hash) from local Docker node:
    // Try OLDEST FIRST order first (blocks 5, 6, 7, 8):
    let blocks_oldest_first = [
        ("066e1aaf9c95c63c48a605064ab514b972709a6a79cbb6ec282eb800c6d10ca1", "91f3ff9b1d2679aa82b372dbd971b977991d276df54d23f0ff4246a1de9c0f3e"), // block 5
        ("3021c29bca61675a7dff943e4a02aa1202f44ccd51756e4cfa36b80a0ccd70b2", "5fc3251cc304589d81439a5215bb131d6bd1f548dca5e1ad44118d5d3fe94f4a"), // block 6
        ("be447d00165b438668ddff65875e7e88a49577b96465ff6fe09abd84b3fb7469", "b8610a49659f92db78e5eb6d3e52111acdcc5ae6c79787ede20e17650363020c"), // block 7
        ("91588f29c2778a178912638f0c27a0c33d821e08cae2e849c3f9251c940d4b24", "23796af64c5fd04940e5746bbee5c92618cd49c9d7c7858dbd91e0fc591d6d17"), // block 8
    ];
    // Try NEWEST FIRST order (blocks 8, 7, 6, 5):
    let blocks_newest_first = [
        ("91588f29c2778a178912638f0c27a0c33d821e08cae2e849c3f9251c940d4b24", "23796af64c5fd04940e5746bbee5c92618cd49c9d7c7858dbd91e0fc591d6d17"), // block 8
        ("be447d00165b438668ddff65875e7e88a49577b96465ff6fe09abd84b3fb7469", "b8610a49659f92db78e5eb6d3e52111acdcc5ae6c79787ede20e17650363020c"), // block 7
        ("3021c29bca61675a7dff943e4a02aa1202f44ccd51756e4cfa36b80a0ccd70b2", "5fc3251cc304589d81439a5215bb131d6bd1f548dca5e1ad44118d5d3fe94f4a"), // block 6
        ("066e1aaf9c95c63c48a605064ab514b972709a6a79cbb6ec282eb800c6d10ca1", "91f3ff9b1d2679aa82b372dbd971b977991d276df54d23f0ff4246a1de9c0f3e"), // block 5
    ];
    let blocks = &blocks_oldest_first; // Try this first

    let ext_msg_root = [0u8; 32]; // test node: no external messages

    // Build block leaves
    let mut data_leaves = Vec::new();
    for (hash_hex, eh_hex) in blocks {
        let block_id = hex_to_bytes(hash_hex);
        let envelope_hash = hex_to_bytes(eh_hex);
        let leaf = compute_block_leaf_hash(&block_id, &envelope_hash, &ext_msg_root);
        println!("block leaf: {}", hex::encode(leaf));
        data_leaves.push(leaf);
    }

    // Assemble tree leaves:
    // [0]: higher_root = zero (no L2 at block 8)
    // [1]: prev_same = L1@4
    // [2-5]: block leaves for blocks 5-8
    // [6-7]: zero padding
    let mut leaves = vec![[0u8; 32], l1_at_4];
    leaves.extend_from_slice(&data_leaves);
    pad_leaves_to_power_of_2(&mut leaves);

    assert_eq!(leaves.len(), 8, "should have 8 leaves");

    let (root, siblings) = build_tree_and_proof(&leaves, 1);
    println!("computed root: {}", hex::encode(root));
    println!("expected root: {}", hex::encode(expected_root));
    println!("siblings: {:?}", siblings.iter().map(|s| hex::encode(s)).collect::<Vec<_>>());

    if root != expected_root {
        println!("oldest-first FAILED, trying newest-first order...\n");

        let mut data_leaves2 = Vec::new();
        for (hash_hex, eh_hex) in &blocks_newest_first {
            let block_id = hex_to_bytes(hash_hex);
            let envelope_hash = hex_to_bytes(eh_hex);
            let leaf = compute_block_leaf_hash(&block_id, &envelope_hash, &ext_msg_root);
            println!("block leaf (newest first): {}", hex::encode(leaf));
            data_leaves2.push(leaf);
        }

        let mut leaves2 = vec![[0u8; 32], l1_at_4];
        leaves2.extend_from_slice(&data_leaves2);
        pad_leaves_to_power_of_2(&mut leaves2);

        let (root2, _) = build_tree_and_proof(&leaves2, 1);
        println!("computed root (newest first): {}", hex::encode(root2));

        assert_eq!(
            root2, expected_root,
            "BOTH orderings failed. oldest-first={}, newest-first={}, expected={}",
            hex::encode(root),
            hex::encode(root2),
            hex::encode(expected_root),
        );
        println!("newest-first order MATCHED!");
    } else {
        println!("oldest-first order MATCHED!");
    }
}

fn hex_to_bytes(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}
