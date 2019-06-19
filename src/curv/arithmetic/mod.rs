/*
    Cryptography utilities

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
*/

mod big_gmp;
mod num_big;
pub mod traits;

#[cfg(feature = "num")]
pub type BigInt = num_big::BigInt;

#[cfg(not(feature = "num"))]
pub type BigInt = big_gmp::BigInt;

#[inline]
pub fn from(bytes: &[u8]) -> BigInt {
    #[cfg(feature = "num")]
    {
        BigInt::from_bytes_be(bytes)
    }
    #[cfg(not(feature = "num"))]
    {
        BigInt::from(bytes)
    }
}
