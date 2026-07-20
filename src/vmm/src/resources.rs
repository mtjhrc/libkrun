// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "tee")]
use std::fs::File;
#[cfg(feature = "tee")]
use std::io::BufReader;
#[cfg(feature = "tee")]
use std::path::Path;

#[cfg(feature = "tee")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "tee")]
use kbs_types::Tee;

/// Errors encountered when loading a TEE configuration file.
#[cfg(feature = "tee")]
#[derive(Debug)]
pub enum Error {
    /// Error opening TEE config file.
    OpenTeeConfig(std::io::Error),
    /// Error parsing TEE config file.
    ParseTeeConfig(serde_json::Error),
}

#[cfg(feature = "tee")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeConfig {
    pub workload_id: String,
    pub cpus: u8,
    pub ram_mib: usize,
    pub tee: Tee,
    pub tee_data: String,
    pub attestation_url: String,
}

#[cfg(feature = "tee")]
impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            workload_id: "".to_string(),
            cpus: 0,
            ram_mib: 0,
            tee: Tee::Sev,
            tee_data: "".to_string(),
            attestation_url: "".to_string(),
        }
    }
}

#[cfg(feature = "tee")]
pub fn load_tee_config(filepath: &Path) -> std::result::Result<TeeConfig, Error> {
    let file = File::open(filepath).map_err(Error::OpenTeeConfig)?;
    let reader = BufReader::new(file);

    serde_json::from_reader(reader).map_err(Error::ParseTeeConfig)
}
