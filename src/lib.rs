// This file is part of BoolNetwork.

// Copyright (C) BoolNetwork (HK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]
#![allow(clippy::all)]
#![allow(warnings)]

#[cfg(all(feature = "std", feature = "mesalock_sgx", target_env = "sgx"))]
#[macro_use]
extern crate std;
#[cfg(all(feature = "std", feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "rand_sgx")]
pub extern crate rand_sgx;

pub extern crate alloc;
#[macro_use]
extern crate lazy_static;
extern crate sha2;

mod one_out_of_many;
mod prf;
pub mod rvrf;
mod traits;
mod util;
mod zero_or_one;

pub mod ed25519;
#[cfg(feature = "pk256")]
pub mod p256;
#[cfg(feature = "pk256")]
pub mod secp256k1;

#[cfg(feature = "prove")]
pub use rvrf::rvrf_prove_simple;
pub use rvrf::rvrf_verify_simple;

#[cfg(test)]
mod tests {

    #[test]
    fn protocol_test() {}
}
