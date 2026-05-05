use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::Context;
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use halo2_base::utils::fs::gen_srs;
use tracing::info;

use attestation_bls_checker_circuit::primary_circuit::PrimaryAttestationBlsCheckerCircuit;

const K: u32 = 20;
const NUM_UNUSABLE_ROWS: usize = 109;
const LOOKUP_BITS: usize = 19;
const LIMB_BITS: usize = 104;
const NUM_LIMBS: usize = 5;
const MAX_SIGNERS: usize = 300;
const SERDE_FMT: SerdeFormat = SerdeFormat::RawBytesUnchecked;

/// Manages SRS, VK, and PK with disk caching.
pub struct KeyManager {
    pub params_dir: PathBuf,
    pub srs: ParamsKZG<Bn256>,
    pub primary_vk: Option<VerifyingKey<G1Affine>>,
    pub primary_pk: Option<ProvingKey<G1Affine>>,
    pub primary_config: Option<BaseCircuitParams>,
}

impl KeyManager {
    /// Create a new KeyManager. Loads SRS (cached by halo2-base).
    /// Attempts to load VK/PK from disk if config exists.
    pub fn new(params_dir: &Path) -> Self {
        std::fs::create_dir_all(params_dir).ok();

        // gen_srs caches to ./params/kzg_bn254_{K}.srs
        let prev_dir = std::env::current_dir().unwrap();
        // Set PARAMS_DIR so gen_srs writes to our params dir
        std::env::set_var("PARAMS_DIR", params_dir.to_str().unwrap());
        let srs = gen_srs(K);
        std::env::set_current_dir(&prev_dir).ok();

        let mut mgr = Self {
            params_dir: params_dir.to_path_buf(),
            srs,
            primary_vk: None,
            primary_pk: None,
            primary_config: None,
        };

        // Try loading cached keys.
        if let Ok(config) = mgr.load_config("primary") {
            info!("found primary config: {:?}", config);
            if let Some(vk) = mgr.try_load_vk("primary", &config) {
                info!("loaded primary VK from cache");
                mgr.primary_vk = Some(vk);
                if let Some(pk) = mgr.try_load_pk("primary", &config) {
                    info!("loaded primary PK from cache");
                    mgr.primary_pk = Some(pk);
                }
            }
            mgr.primary_config = Some(config);
        }

        mgr
    }

    /// Ensure primary circuit keys exist. Runs keygen if not cached.
    pub fn ensure_primary_keys(
        &mut self,
        bk_set: &HashMap<u16, Vec<u8>>,
    ) -> anyhow::Result<()> {
        if self.primary_vk.is_some() && self.primary_pk.is_some() {
            info!("primary keys already loaded");
            return Ok(());
        }

        info!("running keygen for primary circuit (this may take ~60s)...");

        // Build a reference circuit to determine params.
        let test_data =
            bridge_test_data_gen::generator::generate_test_data_all_sign(bk_set.len())
                .context("failed to generate reference test data for keygen")?;

        let last_seen: u32 = 0;
        let circuit = PrimaryAttestationBlsCheckerCircuit::<Fr>::new(
            test_data.attestation_bytes,
            test_data.bk_set,
            last_seen,
            K as usize,
            NUM_UNUSABLE_ROWS,
            LOOKUP_BITS,
            LIMB_BITS,
            NUM_LIMBS,
            MAX_SIGNERS,
        );
        let base_params = circuit.params.base_circuit_params.clone();
        info!("base_circuit_params: {:?}", base_params);

        let t = std::time::Instant::now();
        let vk = keygen_vk(&self.srs, &circuit).context("keygen_vk failed")?;
        info!("keygen_vk: {:?}", t.elapsed());

        let t = std::time::Instant::now();
        let pk = keygen_pk(&self.srs, vk.clone(), &circuit).context("keygen_pk failed")?;
        info!("keygen_pk: {:?}", t.elapsed());

        // Save to disk.
        self.save_vk("primary", &vk)?;
        self.save_pk("primary", &pk)?;
        self.save_config("primary", &base_params)?;

        self.primary_vk = Some(vk);
        self.primary_pk = Some(pk);
        self.primary_config = Some(base_params);

        info!("primary keys generated and cached");
        Ok(())
    }

    pub fn primary_vk(&self) -> &VerifyingKey<G1Affine> {
        self.primary_vk.as_ref().expect("primary VK not loaded")
    }

    pub fn primary_pk(&self) -> &ProvingKey<G1Affine> {
        self.primary_pk.as_ref().expect("primary PK not loaded")
    }

    pub fn primary_config(&self) -> &BaseCircuitParams {
        self.primary_config.as_ref().expect("primary config not loaded")
    }

    // ---- Internal helpers ----

    fn vk_path(&self, prefix: &str) -> PathBuf {
        self.params_dir.join(format!("{}_vk.bin", prefix))
    }

    fn pk_path(&self, prefix: &str) -> PathBuf {
        self.params_dir.join(format!("{}_pk.bin", prefix))
    }

    fn config_path(&self, prefix: &str) -> PathBuf {
        self.params_dir.join(format!("{}_config_params.json", prefix))
    }

    fn load_config(&self, prefix: &str) -> anyhow::Result<BaseCircuitParams> {
        let data = std::fs::read_to_string(self.config_path(prefix))?;
        Ok(serde_json::from_str(&data)?)
    }

    fn save_config(&self, prefix: &str, config: &BaseCircuitParams) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(config)?;
        std::fs::write(self.config_path(prefix), json)?;
        Ok(())
    }

    fn try_load_vk(&self, prefix: &str, config: &BaseCircuitParams) -> Option<VerifyingKey<G1Affine>> {
        let file = std::fs::File::open(self.vk_path(prefix)).ok()?;
        let mut reader = BufReader::new(file);
        VerifyingKey::<G1Affine>::read::<_, BaseCircuitBuilder<Fr>>(
            &mut reader,
            SERDE_FMT,
            config.clone(),
        )
        .ok()
    }

    fn try_load_pk(&self, prefix: &str, config: &BaseCircuitParams) -> Option<ProvingKey<G1Affine>> {
        let file = std::fs::File::open(self.pk_path(prefix)).ok()?;
        let mut reader = BufReader::new(file);
        ProvingKey::<G1Affine>::read::<_, BaseCircuitBuilder<Fr>>(
            &mut reader,
            SERDE_FMT,
            config.clone(),
        )
        .ok()
    }

    fn save_vk(&self, prefix: &str, vk: &VerifyingKey<G1Affine>) -> anyhow::Result<()> {
        let file = std::fs::File::create(self.vk_path(prefix))?;
        let mut writer = BufWriter::new(file);
        vk.write(&mut writer, SERDE_FMT)?;
        Ok(())
    }

    fn save_pk(&self, prefix: &str, pk: &ProvingKey<G1Affine>) -> anyhow::Result<()> {
        let file = std::fs::File::create(self.pk_path(prefix))?;
        let mut writer = BufWriter::new(file);
        pk.write(&mut writer, SERDE_FMT)?;
        Ok(())
    }
}

/// Public constants for use by other modules.
pub const fn circuit_k() -> u32 { K }
pub const fn circuit_limb_bits() -> usize { LIMB_BITS }
pub const fn circuit_num_limbs() -> usize { NUM_LIMBS }
pub const fn circuit_max_signers() -> usize { MAX_SIGNERS }
pub const fn circuit_num_unusable_rows() -> usize { NUM_UNUSABLE_ROWS }
pub const fn circuit_lookup_bits() -> usize { LOOKUP_BITS }
