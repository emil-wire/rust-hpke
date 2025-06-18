//! X-Wing hybrid post-quantum KEM implementation

use crate::{
    kdf::{extract_and_expand, HkdfSha256},
    kem::{Kem as KemTrait, SharedSecret},
    util::{enforce_outbuf_len, kem_suite_id},
    Deserializable, HpkeError, Serializable,
};

use generic_array::GenericArray;

// Use X-Wing crate constants for sizes
use x_wing::{CIPHERTEXT_SIZE, ENCAPSULATION_KEY_SIZE, DECAPSULATION_KEY_SIZE};

// Define X-Wing sizes as type-level integers using crate constants
// Create custom type aliases for the sizes since generic_array doesn't define them
use generic_array::typenum::{U1024, U96, U192, Sum};
type U1120 = Sum<U1024, U96>;  // CIPHERTEXT_SIZE: 1120 bytes  
type U1216 = Sum<U1024, U192>; // ENCAPSULATION_KEY_SIZE: 1216 bytes
type U32 = generic_array::typenum::U32; // DECAPSULATION_KEY_SIZE: 32 bytes

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import KEM traits for x-wing operations
use kem::{Encapsulate, Decapsulate};

// Re-export X-Wing types
pub use x_wing::{DecapsulationKey as XWingPrivateKey, EncapsulationKey as XWingPublicKey};

/// The X-Wing hybrid post-quantum KEM
///
/// X-Wing combines X25519 and ML-KEM-768 to provide a hybrid KEM that offers
/// both classical elliptic curve and post-quantum security. This module
/// wraps RustCryptos X-Wing draft06 implementation.
///
/// **The underlying X-Wing implementation has not been independently audited.**

#[derive(Clone, Copy, Debug)]
pub struct XWing;

/// X-Wing encapsulated key
///
/// This wraps the x-wing ciphertext that contains the encapsulated key material.
#[derive(Clone)]
pub struct XWingEncappedKey(pub(crate) x_wing::Ciphertext);

impl PartialEq for XWingEncappedKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Eq for XWingEncappedKey {}

impl core::fmt::Debug for XWingEncappedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XWingEncappedKey").finish()
    }
}

impl Serializable for XWingEncappedKey {
    type OutputSize = U1120; // X-Wing ciphertext size: 1120 bytes

    fn write_exact(&self, buf: &mut [u8]) {
        enforce_outbuf_len::<Self>(buf);
        buf.copy_from_slice(&self.0.as_bytes());
    }
}

impl Deserializable for XWingEncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != CIPHERTEXT_SIZE {
            return Err(HpkeError::IncorrectInputLength(CIPHERTEXT_SIZE, encoded.len()));
        }

        let bytes: &[u8; CIPHERTEXT_SIZE] = encoded.try_into().map_err(|_| HpkeError::DecapError)?;
        let ciphertext = x_wing::Ciphertext::from(bytes);
        Ok(XWingEncappedKey(ciphertext))
    }
}

/// Wrapper around X-Wing public key to implement required traits
#[derive(Clone)]
pub struct PublicKey(XWingPublicKey);

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKey").finish()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Eq for PublicKey {}

impl Serializable for PublicKey {
    type OutputSize = U1216; // X-Wing encapsulation key size: 1216 bytes

    fn write_exact(&self, buf: &mut [u8]) {
        enforce_outbuf_len::<Self>(buf);
        buf.copy_from_slice(&self.0.as_bytes());
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != ENCAPSULATION_KEY_SIZE {
            return Err(HpkeError::IncorrectInputLength(ENCAPSULATION_KEY_SIZE, encoded.len()));
        }

        let bytes: &[u8; ENCAPSULATION_KEY_SIZE] = encoded.try_into().map_err(|_| HpkeError::DecapError)?;
        let pk = x_wing::EncapsulationKey::from(bytes);
        Ok(PublicKey(pk))
    }
}

/// Wrapper around X-Wing private key to implement required traits
#[derive(Clone)]
pub struct PrivateKey(XWingPrivateKey);

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Eq for PrivateKey {}

impl Serializable for PrivateKey {
    type OutputSize = U32; // X-Wing decapsulation key size: 32 bytes

    fn write_exact(&self, buf: &mut [u8]) {
        enforce_outbuf_len::<Self>(buf);
        buf.copy_from_slice(self.0.as_bytes());
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != DECAPSULATION_KEY_SIZE {
            return Err(HpkeError::IncorrectInputLength(DECAPSULATION_KEY_SIZE, encoded.len()));
        }

        let bytes: [u8; DECAPSULATION_KEY_SIZE] = encoded.try_into().map_err(|_| HpkeError::DecapError)?;
        let sk = x_wing::DecapsulationKey::from(bytes);
        Ok(PrivateKey(sk))
    }
}

// Ensure private keys are zeroized on drop
impl ZeroizeOnDrop for PrivateKey {}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl KemTrait for XWing {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = XWingEncappedKey;

    /// X-Wing uses a 32-byte shared secret (same as SHA256 output)
    type NSecret = U32;

    /// X-Wing KEM identifier (placeholder from draft07 - needs official assignment)
    const KEM_ID: u16 = 0x647a;

    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        // X-Wing uses 32-byte seeds for deterministic key generation
        // We use HKDF to derive a proper seed from arbitrary-length IKM
        let suite_id = kem_suite_id::<Self>();

        // Extract and expand to get a 32-byte seed for X-Wing key generation
        let mut seed = GenericArray::<u8, U32>::default();
        extract_and_expand::<HkdfSha256>(ikm, &suite_id, b"key_gen", &mut seed)
            .expect("KDF output length is valid");

        // Use X-Wing's deterministic key generation from seed
        // The DecapsulationKey::from() method internally uses SHAKE256 expansion
        // as specified in the X-Wing IETF draft for proper key derivation
        let seed_array: [u8; 32] = seed.into();
        let sk = x_wing::DecapsulationKey::from(seed_array);
        let pk = sk.encapsulation_key();

        (PrivateKey(sk), PublicKey(pk))
    }

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        PublicKey(sk.0.encapsulation_key())
    }

    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        _sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        // X-Wing doesn't support authenticated encapsulation in the same way as DHKEM
        // We ignore the sender identity and just do regular encapsulation

        // The published kem crate (v0.3.0-pre.0) uses CryptoRngCore from rand_core 0.6
        // but our RNG implements CryptoRng + RngCore from rand_core 0.9
        // We need an adapter to bridge the compatibility gap
        // TODO: remove this ugly hack
        struct RngAdapter<R>(R);
        
        impl<R: RngCore> aead::rand_core::RngCore for RngAdapter<R> {
            fn next_u32(&mut self) -> u32 { self.0.next_u32() }
            fn next_u64(&mut self) -> u64 { self.0.next_u64() }
            fn fill_bytes(&mut self, dest: &mut [u8]) { self.0.fill_bytes(dest) }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), aead::rand_core::Error> {
                self.0.fill_bytes(dest); Ok(())
            }
        }
        
        impl<R: CryptoRng> aead::rand_core::CryptoRng for RngAdapter<R> {}

        let mut adapter = RngAdapter(csprng);
        let (ciphertext, shared_secret) = pk_recip.0.encapsulate(&mut adapter)
            .map_err(|_| HpkeError::EncapError)?;

        // Convert x-wing shared secret to our SharedSecret type
        let mut our_shared_secret = SharedSecret::<Self>::default();
        our_shared_secret.0.copy_from_slice(&shared_secret);

        Ok((our_shared_secret, XWingEncappedKey(ciphertext)))
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        _pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        // X-Wing doesn't support authenticated decapsulation in the same way as DHKEM
        // We ignore the sender identity for now and just do regular decapsulation

        // Use the x-wing KEM trait
        let shared_secret = sk_recip.0.decapsulate(&encapped_key.0)
            .map_err(|_| HpkeError::DecapError)?;

        // Convert x-wing shared secret to our SharedSecret type
        let mut our_shared_secret = SharedSecret::<Self>::default();
        our_shared_secret.0.copy_from_slice(&shared_secret);

        Ok(our_shared_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_x_wing_encap_decap() {
        let mut csprng = StdRng::from_os_rng();
        let (sk_recip, pk_recip) = XWing::gen_keypair(&mut csprng);

        // Test basic encapsulation and decapsulation
        let (shared_secret1, encapped_key) = XWing::encap(&pk_recip, None, &mut csprng).unwrap();
        let shared_secret2 = XWing::decap(&sk_recip, None, &encapped_key).unwrap();

        assert_eq!(shared_secret1.0, shared_secret2.0);
    }

    #[test]
    fn test_x_wing_derive_keypair() {
        let ikm = b"this is some input keying material";
        let (sk1, pk1) = XWing::derive_keypair(ikm);
        let (sk2, pk2) = XWing::derive_keypair(ikm);

        // Deterministic key derivation should produce the same keys
        assert_eq!(pk1, pk2);
        // Compare private keys by serialization since they don't implement Debug
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn test_x_wing_sk_to_pk() {
        let mut csprng = StdRng::from_os_rng();
        let (sk, pk) = XWing::gen_keypair(&mut csprng);
        let derived_pk = XWing::sk_to_pk(&sk);

        assert_eq!(pk, derived_pk);
    }

    #[test]
    fn test_x_wing_serialization() {
        let mut csprng = StdRng::from_os_rng();
        let (sk, pk) = XWing::gen_keypair(&mut csprng);
        let (_, encapped_key) = XWing::encap(&pk, None, &mut csprng).unwrap();

        // Test public key serialization
        let pk_bytes = pk.to_bytes();
        let pk_recovered = PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk, pk_recovered);

        // Test private key serialization
        let sk_bytes = sk.to_bytes();
        let sk_recovered = PrivateKey::from_bytes(&sk_bytes).unwrap();
        // Compare by serialization since they don't implement Debug
        assert_eq!(sk.to_bytes(), sk_recovered.to_bytes());

        // Test encapped key serialization
        let ek_bytes = encapped_key.to_bytes();
        let ek_recovered = XWingEncappedKey::from_bytes(&ek_bytes).unwrap();
        // We can't directly compare encapped keys, so we'll test by decapsulation
        let ss1 = XWing::decap(&sk, None, &encapped_key).unwrap();
        let ss2 = XWing::decap(&sk, None, &ek_recovered).unwrap();
        assert_eq!(ss1.0, ss2.0);
    }
}