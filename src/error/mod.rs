// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

mod coserv;
mod discovery;

pub use coserv::*;
pub use discovery::*;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Discovery(#[from] DiscoveryError),
    #[error("{0}")]
    Coserv(#[from] CoservError),
    #[error("Unclassified CoSERV error.")]
    Unknown,
}
