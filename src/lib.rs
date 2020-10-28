//! # BIP-85 deterministic entropy generation

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

extern crate bitcoin;

use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::bip32::DerivationPath;
use bitcoin::util::bip32::ChildNumber;
use bitcoin::util::bip32::Error;
use bitcoin::util::key::PrivateKey;
use bitcoin::hashes::{hmac, sha512, Hash, HashEngine};

/// Derive raw bytes from the root key using provided derivation path.
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
        path: &P
    ) -> Result<Vec<u8>, Error> {
    const BIP85_CHILD_NUMBER: ChildNumber = ChildNumber::Hardened{ index: 83696968 };
    let bip85_root = root.ckd_priv(secp, BIP85_CHILD_NUMBER)?;
    let derived = bip85_root.derive_priv(secp, &path)?;
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
        index: u32
    ) -> Result<PrivateKey, Error> {
    const BIP85_WIF_INDEX: ChildNumber = ChildNumber::Hardened{ index: 2 };
    let path = DerivationPath::from(vec![BIP85_WIF_INDEX, ChildNumber::from_hardened_idx(index).unwrap()]);
    let data = derive(secp, root, &path)?;
    Ok(PrivateKey {
            compressed: true,
            network: root.network,
            key: SecretKey::from_slice(&data[0..32])?,
    })
}

// pub fn derive_mnemonic<C: secp256k1::Signing>(
//        secp: &Secp256k1<C>,
//        root: &ExtendedPrivKey,
//        index: u32
//    ) -> Result<Priva

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
    }
}
