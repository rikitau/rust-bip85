extern crate bip85;

use std::str::FromStr;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::ExtendedPrivKey;
use bip39::Language;

fn main(){
    let root = ExtendedPrivKey::from_str(
        "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaL\
         LHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
    ).unwrap();
    let secp = Secp256k1::new();

    let mnemonic = bip85::to_mnemonic(&secp, &root, 12, 0).unwrap();
    println!("12-word mnemonic:\n{}", mnemonic);

    let mnemonic = bip85::to_mnemonic(&secp, &root, 24, 0).unwrap();
    println!("24-word mnemonic:\n{}", mnemonic);

    let mnemonic = bip85::to_mnemonic_in(&secp, &root, Language::Japanese, 18, 0).unwrap();
    println!("18-word mnemonic in Japanese:\n{}", mnemonic);
}
