/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 *
*/

mod algorithm;
mod canonicalization;
mod public_key;
mod signature;
mod verify;

pub use public_key::KeyError;

/// The result of the verification of a DKIM signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Result {
    /// TODO: should be an enum
    pub status: String,
}

#[cfg(test)]
mod tests {
    mod hash_header;
}

const MINIMUM_ACCEPTABLE_KEY_SIZE: usize = 1024;

pub use algorithm::{HashAlgorithm, SigningAlgorithm};
pub use canonicalization::{Canonicalization, CanonicalizationAlgorithm};
pub use public_key::PublicKey;
pub use signature::Signature;
pub use verify::VerifierError;
