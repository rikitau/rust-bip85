// Rust implementation of bip-85
// Written in 2020 by
//     Rita Kitic <rikitau@protonmail.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.


//! # BIP-85 deterministic entropy generation

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

extern crate bitcoin;
#[cfg(feature = "mnemonic")]
extern crate bip39;

use std::fmt;
use std::default::Default;

use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
use bitcoin::util::bip32;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::bip32::DerivationPath;
use bitcoin::util::bip32::ChildNumber;
use bitcoin::util::key::PrivateKey;
use bitcoin::hashes::{hmac, sha512, Hash, HashEngine};

#[cfg(feature = "mnemonic")]
use bip39::Mnemonic;

/// A BIP85 error.
#[derive(Clone, PartialEq, Eq)]
pub enum Error {
    /// Hardened index is provided, but only non-hardened indexes are allowed
    InvalidIndex(u32),
    /// Wrong number of bytes requested
    InvalidLength(u32),
    /// Wrong number of words for mnemonic
    InvalidWordCount(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidIndex(index) => write!(f,
                "invalid index for derivation, should be less than 0x80000000: {}", index,
            ),
            Error::InvalidLength(len) => write!(f,
                "invalid bytes length: {}. Should be between 16 and 64", len,
            ),
            Error::InvalidWordCount(word_count) => write!(f,
                "invalid number of words for mnemonic: {}. Should be 12, 18 or 24", word_count,
            ),
        }
    }
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}


/// Derive raw bytes from the root key using provided derivation path.
///
/// Use this function only for custom applications,
/// for standardized applications use application-specific functions - derive_priv,
/// derive_mnemonic, derive_hex.
///
/// Derivation path should start after initial bip85 index (83696968')
/// So to get entropy for WIF private key (app_no 2) with index 1
/// use DerivationPath::from_str("m/2'/0').
pub fn derive<C: secp256k1::Signing, P: AsRef<[ChildNumber]>>(
        secp: &Secp256k1<C>,
        root: &ExtendedPrivKey,
        path: &P,
    ) -> Result<Vec<u8>, Error> {
    const BIP85_CHILD_NUMBER: ChildNumber = ChildNumber::Hardened{ index: 83696968 };
    let bip85_root = root.ckd_priv(secp, BIP85_CHILD_NUMBER).unwrap();
    let derived = bip85_root.derive_priv(secp, &path).unwrap();
    let mut h = hmac::HmacEngine::<sha512::Hash>::new("bip-entropy-from-k".as_bytes());
    h.input(&derived.private_key.to_bytes());
    let data = hmac::Hmac::from_engine(h).into_inner();
    Ok(data.to_vec())
}


/// Derive Bitcoin Private Key from the root key
///
/// See https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#hd-seed-wif
pub fn derive_priv<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        root: &ExtendedPrivKey,
        index: u32,
    ) -> Result<PrivateKey, Error> {
    const BIP85_WIF_INDEX: ChildNumber = ChildNumber::Hardened{ index: 2 };
    if index >= 0x80000000 {
        return Err(Error::InvalidIndex(index));
    }
    let path = DerivationPath::from(vec![BIP85_WIF_INDEX, ChildNumber::from_hardened_idx(index).unwrap()]);
    let data = derive(secp, root, &path)?;
    Ok(PrivateKey {
            compressed: true,
            network: root.network,
            key: SecretKey::from_slice(&data[0..32]).unwrap(),
    })
}

/// Derive bip32 extended private key from root xprv
pub fn derive_xprv<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        root: &ExtendedPrivKey,
        index: u32,
    ) -> Result<ExtendedPrivKey, Error> {
    const BIP85_BIP32_INDEX: ChildNumber = ChildNumber::Hardened{ index: 32 };
    if index >= 0x80000000 {
        return Err(Error::InvalidIndex(index));
    }
    let path = DerivationPath::from(vec![BIP85_BIP32_INDEX, ChildNumber::from_hardened_idx(index).unwrap()]);
    let data = derive(secp, root, &path)?;
    Ok(ExtendedPrivKey {
            network: root.network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal{index: 0},
            private_key: PrivateKey {
                compressed: true,
                network: root.network,
                key: SecretKey::from_slice(
                    &data[32..]
                ).unwrap(),
        },
        chain_code: bip32::ChainCode::from(&data[..32]),
    })
}

/// Derive binary entropy of certain length from the root key
///
/// The length can be from 16 to 64.
pub fn derive_hex<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        root: &ExtendedPrivKey,
        length: u32,
        index: u32,
    ) -> Result<Vec<u8>, Error> {
    const BIP85_HEX_INDEX: ChildNumber = ChildNumber::Hardened{ index: 128169 };
    if length < 16 || length > 64 {
        return Err(Error::InvalidLength(length));
    }
    if index >= 0x80000000 {
        return Err(Error::InvalidIndex(index));
    }
    let path = DerivationPath::from(vec![BIP85_HEX_INDEX,
                                         ChildNumber::from_hardened_idx(length).unwrap(),
                                         ChildNumber::from_hardened_idx(index).unwrap()
    ]);
    let data = derive(secp, root, &path)?;
    Ok(data[0..length as usize].to_vec())
}

/// Derive mnemonic from the xprv key
#[cfg(feature = "mnemonic")]
pub fn derive_mnemonic<C: secp256k1::Signing>(
       secp: &Secp256k1<C>,
       root: &ExtendedPrivKey,
       word_count: u32,
       index: u32,
   ) -> Result<Mnemonic, Error>{
    if word_count < 12 || word_count > 24 || word_count % 6 != 0 {
        return Err(Error::InvalidWordCount(word_count));
    }
    if index >= 0x80000000 {
        return Err(Error::InvalidIndex(index));
    }
    const BIP85_BIP39_INDEX: ChildNumber = ChildNumber::Hardened{ index: 39 };
    let path = DerivationPath::from(vec![BIP85_BIP39_INDEX,
                                         ChildNumber::Hardened { index: 0 }, // English
                                         ChildNumber::from_hardened_idx(word_count).unwrap(),
                                         ChildNumber::from_hardened_idx(index).unwrap()
    ]);
    let data = derive(secp, root, &path)?;
    let len = word_count * 4 / 3;
    let mnemonic = Mnemonic::from_entropy(&data[0..len as usize]).unwrap();
    Ok(mnemonic)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::util::bip32::{ExtendedPrivKey,DerivationPath};
    use bitcoin::util::key::PrivateKey;

    // test vectors from https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
    #[test]
    fn test_raw() {
        let root = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").unwrap();
        let secp = Secp256k1::new();

        let path = DerivationPath::from_str("m/0'/0'").unwrap();
        let derived = derive(&secp, &root, &path).unwrap();
        let expected = vec![0xef, 0xec, 0xfb, 0xcc, 0xff, 0xea, 0x31, 0x32,
                            0x14, 0x23, 0x2d, 0x29, 0xe7, 0x15, 0x63, 0xd9,
                            0x41, 0x22, 0x9a, 0xfb, 0x43, 0x38, 0xc2, 0x1f,
                            0x95, 0x17, 0xc4, 0x1a, 0xaa, 0x0d, 0x16, 0xf0,
                            0x0b, 0x83, 0xd2, 0xa0, 0x9e, 0xf7, 0x47, 0xe7,
                            0xa6, 0x4e, 0x8e, 0x2b, 0xd5, 0xa1, 0x48, 0x69,
                            0xe6, 0x93, 0xda, 0x66, 0xce, 0x94, 0xac, 0x2d,
                            0xa5, 0x70, 0xab, 0x7e, 0xe4, 0x86, 0x18, 0xf7,
        ];
        assert_eq!(expected, derived);

        let path = DerivationPath::from_str("m/0'/1'").unwrap();
        let derived = derive(&secp, &root, &path).unwrap();
        let expected = vec![0x70, 0xc6, 0xe3, 0xe8, 0xeb, 0xee, 0x8d, 0xc4,
                            0xc0, 0xdb, 0xba, 0x66, 0x07, 0x68, 0x19, 0xbb,
                            0x8c, 0x09, 0x67, 0x25, 0x27, 0xc4, 0x27, 0x7c,
                            0xa8, 0x72, 0x95, 0x32, 0xad, 0x71, 0x18, 0x72,
                            0x21, 0x8f, 0x82, 0x69, 0x19, 0xf6, 0xb6, 0x72,
                            0x18, 0xad, 0xde, 0x99, 0x01, 0x8a, 0x6d, 0xf9,
                            0x09, 0x5a, 0xb2, 0xb5, 0x8d, 0x80, 0x3b, 0x5b,
                            0x93, 0xec, 0x98, 0x02, 0x08, 0x5a, 0x69, 0x0e,
        ];
        assert_eq!(expected, derived);
    }

    #[test]
    fn test_priv() {
        let root = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").unwrap();
        let secp = Secp256k1::new();
        let derived = derive_priv(&secp, &root, 0).unwrap();
        let expected = PrivateKey::from_str("Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp").unwrap();

        assert_eq!(expected, derived);

        let index = 0x80000000+1;
        let derived = derive_priv(&secp, &root, index);
        assert_eq!(derived, Err(Error::InvalidIndex(index)));
    }

    #[test]
    fn test_xprv() {
        let root = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").unwrap();
        let secp = Secp256k1::new();

        let derived = derive_xprv(&secp, &root, 0).unwrap();
        let expected = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX").unwrap();

        assert_eq!(expected, derived);
    }

    #[test]
    fn test_hex() {
        let root = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").unwrap();
        let secp = Secp256k1::new();
        let derived = derive_hex(&secp, &root, 64, 0).unwrap();
        let expected = vec![0x49, 0x2d, 0xb4, 0x69, 0x8c, 0xf3, 0xb7, 0x3a,
                            0x5a, 0x24, 0x99, 0x8a, 0xa3, 0xe9, 0xd7, 0xfa,
                            0x96, 0x27, 0x5d, 0x85, 0x72, 0x4a, 0x91, 0xe7,
                            0x1a, 0xa2, 0xd6, 0x45, 0x44, 0x2f, 0x87, 0x85,
                            0x55, 0xd0, 0x78, 0xfd, 0x1f, 0x1f, 0x67, 0xe3,
                            0x68, 0x97, 0x6f, 0x04, 0x13, 0x7b, 0x1f, 0x7a,
                            0x0d, 0x19, 0x23, 0x21, 0x36, 0xca, 0x50, 0xc4,
                            0x46, 0x14, 0xaf, 0x72, 0xb5, 0x58, 0x2a, 0x5c,
        ];

        assert_eq!(expected, derived);

        let derived = derive_hex(&secp, &root, 35, 0).unwrap();
        assert_eq!(derived.len(), 35);

        let derived = derive_hex(&secp, &root, 15, 0);
        assert_eq!(derived, Err(Error::InvalidLength(15)));

        let derived = derive_hex(&secp, &root, 65, 0);
        assert_eq!(derived, Err(Error::InvalidLength(65)));
    }

    #[cfg(feature = "mnemonic")]
    #[test]
    fn test_mnemonic() {
        let root = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").unwrap();
        let secp = Secp256k1::new();

        let derived = derive_mnemonic(&secp, &root, 12, 0).unwrap();
        let expected = Mnemonic::from_str("girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose").unwrap();
        assert_eq!(derived, expected);

        let derived = derive_mnemonic(&secp, &root, 18, 0).unwrap();
        let expected = Mnemonic::from_str("near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token").unwrap();
        assert_eq!(derived, expected);

        let derived = derive_mnemonic(&secp, &root, 24, 0).unwrap();
        let expected = Mnemonic::from_str("puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano").unwrap();
        assert_eq!(derived, expected);
    }
}
