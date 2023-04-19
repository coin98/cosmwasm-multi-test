use cosmwasm_crypto;
use cosmwasm_std::{Addr, Api, CanonicalAddr, RecoverPubkeyError, StdError, StdResult, VerificationError};
use bech32::{FromBase32, ToBase32};

pub struct MockApi {
}

impl Default for MockApi {
    fn default() -> Self {
        MockApi {}
    }
}

impl Api for MockApi {
    fn addr_validate(&self, input: &str) -> StdResult<Addr> {
        let canonical = self.addr_canonicalize(input)?;
        let normalized = self.addr_humanize(&canonical)?;
        if input != normalized {
            return Err(StdError::generic_err(
                "Invalid input: address not normalized",
            ));
        }

        Ok(Addr::unchecked(input))
    }

    fn addr_canonicalize(&self, input: &str) -> StdResult<CanonicalAddr> {
        if input.starts_with("wasm1") {
            let (_, canonical_base32, _) = bech32::decode(input).unwrap();
            let canonical =  Vec::<u8>::from_base32(&canonical_base32).unwrap();
            let canonical_address = CanonicalAddr::from(&canonical[..]);
            return Ok(canonical_address);
        }
        let input_buffer = input.as_bytes();
        let mut canonical = vec![17, 17, 17, 17];
        canonical.extend_from_slice(input_buffer);
        let canonical_address = CanonicalAddr::from(&canonical[..]);
        Ok(canonical_address)
    }

    fn addr_humanize(&self, canonical_address: &CanonicalAddr) -> StdResult<Addr> {
        let canonical = canonical_address.as_slice();
        if canonical.len() > 4
          && canonical[0] == 17
          && canonical[1] == 17
          && canonical[2] == 17
          && canonical[3] == 17 {
            let output_buffer = &canonical[4..];
            let address = String::from_utf8(output_buffer.to_vec()).unwrap();
            let humanized_address = Addr::unchecked(address);
            return Ok(humanized_address);
        }
        let bech32_address = bech32::encode("wasm", &canonical_address.as_slice().to_base32(), bech32::Variant::Bech32).unwrap();
        let humanized_address = Addr::unchecked(bech32_address);
        Ok(humanized_address)
    }

    fn secp256k1_verify(
        &self,
        message_hash: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, VerificationError> {
        Ok(cosmwasm_crypto::secp256k1_verify(
            message_hash,
            signature,
            public_key,
        )?)
    }

    fn secp256k1_recover_pubkey(
        &self,
        message_hash: &[u8],
        signature: &[u8],
        recovery_param: u8,
    ) -> Result<Vec<u8>, RecoverPubkeyError> {
        let pubkey =
            cosmwasm_crypto::secp256k1_recover_pubkey(message_hash, signature, recovery_param)?;
        Ok(pubkey.to_vec())
    }

    fn ed25519_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, VerificationError> {
        Ok(cosmwasm_crypto::ed25519_verify(
            message, signature, public_key,
        )?)
    }

    fn ed25519_batch_verify(
        &self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<bool, VerificationError> {
        Ok(cosmwasm_crypto::ed25519_batch_verify(
            messages,
            signatures,
            public_keys,
        )?)
    }

    fn debug(&self, message: &str) {
        println!("{}", message);
    }
}
