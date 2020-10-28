extern crate bip85;

//use bip85;
use std::str::FromStr;
// use std::io;

// use bip39::Mnemonic;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::ExtendedPrivKey;

fn main(){
    let root = ExtendedPrivKey::from_str("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb").unwrap();
    println!("{}", root);
    let secp = Secp256k1::new();
    let derived = bip85::derive_priv(&secp, &root, 0).unwrap();
    println!("{}", derived);

    let data = bip85::derive_hex(&secp, &root, 35, 0).unwrap();
    println!("{:x?}", data);
}
