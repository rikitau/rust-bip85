use std::str::FromStr;
// use std::io;

// use bip39::Mnemonic;
use bitcoin::secp256k1;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::bip32::DerivationPath;
use bitcoin::util::bip32::ChildNumber;
use bitcoin::hashes::{hmac, sha512, Hash, HashEngine};
// use bitcoin::network::constants::Network;
use bitcoin::util::bip32::Error;
use bitcoin::util::key::PrivateKey;

fn derive<C: secp256k1::Signing, P: AsRef<[ChildNumber]>>(
        secp: &Secp256k1<C>,
        root: &ExtendedPrivKey,
        path: &P,
    ) -> Result<PrivateKey, Error> {
    let derived = root.derive_priv(secp, path)?;
    let mut h = hmac::HmacEngine::<sha512::Hash>::new("bip-entropy-from-k".as_bytes());
    h.input(&derived.private_key.to_bytes());
    let data = hmac::Hmac::from_engine(h).into_inner();
    Ok(PrivateKey {
            compressed: true,
            network: derived.network,
            key: SecretKey::from_slice(&data[0..32])?,
    })
}

fn main(){
    let root = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").unwrap();
    println!("{}", root);
    let secp = Secp256k1::new();
    let path = DerivationPath::from_str("m/83696968'/2'/0'").unwrap();
    let derived = derive(&secp, &root, &path).unwrap();
    println!("{}", derived);
}
