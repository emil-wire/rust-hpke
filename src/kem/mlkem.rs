//! The pure ML-KEM-768 and ML-KEM-1024 HPKE KEMs, as currently specified in
//! <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04> §3.
//!
//! **EXPERIMENTAL:** these KEMs are based on `draft-ietf-hpke-pq-04`, an unratified IETF draft.
//! The construction and its identifiers are subject to change until the draft is finalized, so the
//! wire format is not yet stable. Treat these KEMs as experimental.
//!
//! Unlike the hybrid KEMs in this crate, these use the ML-KEM shared secret directly as the HPKE
//! shared secret (no ExtractAndExpand/KDF wrapping). The private key is the 64-byte ML-KEM seed
//! `d‖z`, NOT the FIPS-203 expanded decapsulation key.

use crate::{
    kdf::one_stage_kdf::labeled_derive,
    kem::{KemTrait, SharedSecret},
    util::{enforce_equal_len, enforce_outbuf_len, kem_suite_id},
    Deserializable, HpkeError, Serializable,
};

use hybrid_array::typenum::{Unsigned, U32, U64};
#[cfg(feature = "mlkem1024")]
use ml_kem::MlKem1024 as MlKem1024Params;
#[cfg(feature = "mlkem768")]
use ml_kem::MlKem768 as MlKem768Params;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem as KemCore},
    Ciphertext, DecapsulationKey, EncapsulationKey, FromSeed, KeyExport, KeySizeUser,
};
use rand_core::CryptoRng;
use sha3::Shake256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Parameters:
/// - `$kem` - the name of the KEM struct to define (e.g. `MlKem768`)
/// - `$param` - the `ml_kem` parameter set type (e.g. `MlKem768Params`)
/// - `$pk`, `$sk`, `$enc` - names for the public-key, private-key, and encapsulated-key structs
/// - `kem_id = $kem_id` - the HPKE KEM identifier from draft-ietf-hpke-pq-04 §3
/// - `$name` - a string literal used in assertion messages (e.g. `"ML-KEM-768"`)
///
/// Wire sizes (`Nenc`, `Npk`, `Nsk`) are derived automatically from the `ml_kem` type-level
/// constants (`CiphertextSize`, `KeySize`, etc.) rather than being supplied as macro arguments.
macro_rules! define_mlkem {
    (
        $(#[$kem_doc:meta])*
        $kem:ident,
        $param:ty,
        $pk:ident,
        $sk:ident,
        $enc:ident,
        kem_id = $kem_id:expr,
        $name:literal
    ) => {
        /// An ML-KEM private key. This is the 64-byte seed `d‖z`, per draft-ietf-hpke-pq-04 §3.
        #[derive(Clone)]
        pub struct $sk {
            seed: [u8; 64],
        }

        impl Drop for $sk {
            fn drop(&mut self) {
                self.seed.zeroize();
            }
        }
        impl ZeroizeOnDrop for $sk {}

        impl ConstantTimeEq for $sk {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.seed.ct_eq(&other.seed)
            }
        }

        impl PartialEq for $sk {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }
        impl Eq for $sk {}

        impl Serializable for $sk {
            // Nsk = 64 per draft-ietf-hpke-pq-04 §3
            type OutputSize = U64;

            fn write_exact(&self, buf: &mut [u8]) {
                // Check the length is correct and panic if not
                enforce_outbuf_len::<Self>(buf);
                // The serialized private key is the seed itself (identity)
                buf.copy_from_slice(&self.seed);
            }
        }

        impl Deserializable for $sk {
            fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
                let seed = encoded.try_into().map_err(|_| {
                    HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
                })?;
                Ok(Self { seed })
            }
        }

        /// An ML-KEM public key, i.e., an ML-KEM encapsulation key.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $pk(EncapsulationKey<$param>);

        impl Serializable for $pk {
            // Npk per draft-ietf-hpke-pq-04 §3
            type OutputSize = <EncapsulationKey<$param> as KeySizeUser>::KeySize;

            fn write_exact(&self, buf: &mut [u8]) {
                // Check the length is correct and panic if not
                enforce_outbuf_len::<Self>(buf);
                // Serialize is identity over the fixed-length encapsulation key
                buf.copy_from_slice(&self.0.to_bytes());
            }
        }

        impl Deserializable for $pk {
            fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
                // Check the input buf length is correct and error if not
                enforce_equal_len(Self::OutputSize::USIZE, encoded.len())?;
                // Infallible because of the check above
                let ek = EncapsulationKey::<$param>::new(encoded.try_into().expect("correct length"))
                    .map_err(|_| HpkeError::ValidationError)?;
                Ok($pk(ek))
            }
        }

        /// An ML-KEM encapsulated key, i.e., an ML-KEM ciphertext.
        #[derive(Clone)]
        pub struct $enc(Ciphertext<$param>);

        impl Serializable for $enc {
            // Nenc per draft-ietf-hpke-pq-04 §3
            type OutputSize = <$param as KemCore>::CiphertextSize;

            fn write_exact(&self, buf: &mut [u8]) {
                // Check the length is correct and panic if not
                enforce_outbuf_len::<Self>(buf);
                // Serialize is identity over the fixed-length ciphertext
                buf.copy_from_slice(&self.0);
            }
        }

        impl Deserializable for $enc {
            fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
                // Check the input buf length is correct and error if not
                enforce_equal_len(Self::OutputSize::USIZE, encoded.len())?;
                // Infallible because of the check above
                let ct = Ciphertext::<$param>::try_from(encoded).expect("correct length");
                Ok($enc(ct))
            }
        }

        $(#[$kem_doc])*
        pub struct $kem;

        impl KemTrait for $kem {
            // Nsecret = 32 per draft-ietf-hpke-pq-04 §3. The HPKE shared secret is the ML-KEM
            // shared secret directly.
            type NSecret = U32;
            // Value from draft-ietf-hpke-pq-04 §3
            const KEM_ID: u16 = $kem_id;

            type PublicKey = $pk;
            type PrivateKey = $sk;
            type EncappedKey = $enc;

            fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
                // expandDecapsKey(dk): (ek, expanded_dk) = ML-KEM.KeyGen_internal(d, z)
                let mut seed_arr = sk.seed.into();
                let (_, ek) = <$param as FromSeed>::from_seed(&seed_arr);
                seed_arr[..].zeroize();
                $pk(ek)
            }

            // From draft-ietf-hpke-pq-04 §3:
            //   def DeriveKeyPair(ikm):
            //     dk = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 64)
            //     (_, ek) = expandDecapsKey(dk)
            //     return (dk, ek)
            fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
                let mut seed = [0u8; 64];
                let suite_id = kem_suite_id::<Self>();
                labeled_derive::<Shake256>(
                    &suite_id,
                    &[ikm],
                    b"DeriveKeyPair",
                    &[b""],
                    &mut seed,
                );

                let mut seed_arr = seed.into();
                let (_, ek) = <$param as FromSeed>::from_seed(&seed_arr);
                seed_arr[..].zeroize();
                ($sk { seed }, $pk(ek))
            }

            /// Decapsulate the encapsulated key using the recipient's private key. This DOES NOT
            /// support authenticated encapsulation, i.e., `pk_sender_id` MUST be `None`.
            ///
            /// # Panics
            /// Panics if `pk_sender_id` is `Some`.
            // From draft-ietf-hpke-pq-04 §3:
            //   def Decap(enc, skR):
            //     (expanded_dk, _) = expandDecapsKey(skR)
            //     return ML-KEM.Decaps(expanded_dk, enc)
            fn decap(
                sk_recip: &Self::PrivateKey,
                pk_sender_id: Option<&Self::PublicKey>,
                encapped_key: &Self::EncappedKey,
            ) -> Result<SharedSecret<Self>, HpkeError> {
                assert!(
                    pk_sender_id.is_none(),
                    concat!(
                        $name,
                        " doesn't support authenticated encapsulation. Use Base or Psk operation mode."
                    )
                );

                let mut seed_arr = sk_recip.seed.into();
                let (dk, _) = <$param as FromSeed>::from_seed(&seed_arr);
                seed_arr[..].zeroize();
                let ss = DecapsulationKey::<$param>::decapsulate(&dk, &encapped_key.0);
                Ok(SharedSecret(ss))
            }

            /// Derives a shared secret and an ephemeral pubkey that the owner of the recipient's
            /// pubkey can use to derive the same shared secret. This DOES NOT support authenticated
            /// encapsulation, i.e., `sender_id_keypair` MUST be `None`.
            ///
            /// # Panics
            /// Panics if `sender_id_keypair` is `Some`.
            // From draft-ietf-hpke-pq-04 §3:
            //   def Encap(pkR):
            //     (shared_secret, enc) = ML-KEM.Encaps(pkR)
            //     return (shared_secret, enc)
            fn encap_with_rng(
                pk_recip: &Self::PublicKey,
                sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
                csprng: &mut impl CryptoRng,
            ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
                assert!(
                    sender_id_keypair.is_none(),
                    concat!(
                        $name,
                        " doesn't support authenticated encapsulation. Use Base or Psk operation mode."
                    )
                );

                let (ct, ss) = pk_recip.0.encapsulate_with_rng(csprng);
                Ok((SharedSecret(ss), $enc(ct)))
            }
        }

        // Impl the trait necessary for known-answer tests
        #[cfg(all(test, feature = "kat"))]
        impl crate::kat_tests::TestableKem for $kem {
            // There is no encap-with-eph, since that only makes sense for DHKEMs
            type EphemeralKey = core::convert::Infallible;
            fn encap_with_eph(
                _pk_recip: &Self::PublicKey,
                _sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
                _sk_eph: Self::EphemeralKey,
            ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
                unimplemented!()
            }

            fn encap_det(
                pk_recip: &Self::PublicKey,
                sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
                randomness: &[u8],
            ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
                assert!(
                    sender_id_keypair.is_none(),
                    concat!($name, " doesn't support authenticated encapsulation")
                );

                use rand_core::{TryCryptoRng, TryRng};
                struct FakeCsprng<'a> {
                    randomness: &'a [u8],
                }
                impl<'a> TryRng for FakeCsprng<'a> {
                    type Error = core::convert::Infallible;

                    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                        rand_core::utils::next_word_via_fill(self)
                    }

                    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                        rand_core::utils::next_word_via_fill(self)
                    }

                    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
                        if dest.len() > self.randomness.len() {
                            unreachable!("ran out of randomness")
                        } else {
                            let (taken, rest) = self.randomness.split_at(dest.len());
                            dest.copy_from_slice(taken);
                            self.randomness = rest;
                            Ok(())
                        }
                    }
                }
                impl<'a> TryCryptoRng for FakeCsprng<'a> {}

                $kem::encap_with_rng(
                    pk_recip,
                    sender_id_keypair,
                    &mut FakeCsprng { randomness },
                )
            }
        }
    };
}

#[cfg(feature = "mlkem768")]
define_mlkem!(
    /// Represents the pure ML-KEM-768 post-quantum KEM.
    MlKem768,
    MlKem768Params,
    PublicKey768,
    PrivateKey768,
    EncappedKey768,
    kem_id = 0x0041,
    "ML-KEM-768"
);

#[cfg(feature = "mlkem1024")]
define_mlkem!(
    /// Represents the pure ML-KEM-1024 post-quantum KEM.
    MlKem1024,
    MlKem1024Params,
    PublicKey1024,
    PrivateKey1024,
    EncappedKey1024,
    kem_id = 0x0042,
    "ML-KEM-1024"
);

#[cfg(test)]
mod tests {
    #[cfg(feature = "mlkem1024")]
    use super::MlKem1024;
    #[cfg(feature = "mlkem768")]
    use super::MlKem768;
    use crate::{Deserializable, Kem as KemTrait, Serializable};

    macro_rules! test_encap_correctness {
        ($test_name:ident, $kem_ty:ty) => {
            /// Tests that encap and decap produce the same shared secret when composed
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                let mut csprng = rand::rng();
                let (sk_recip, pk_recip) = Kem::gen_keypair_with_rng(&mut csprng);

                let (shared_secret, encapped_key) =
                    Kem::encap_with_rng(&pk_recip, None, &mut csprng)
                        .expect("encapsulation failed");
                let decapped_shared_secret =
                    Kem::decap(&sk_recip, None, &encapped_key).expect("decapsulation failed");

                assert_eq!(shared_secret.0, decapped_shared_secret.0);
            }
        };
    }

    macro_rules! test_encapped_serialize {
        ($test_name:ident, $kem_ty:ty) => {
            /// Tests that a serialize-deserialize round trip on an encapped key is the identity
            #[test]
            fn $test_name() {
                type Kem = $kem_ty;

                let mut csprng = rand::rng();
                let (_, pk_recip) = Kem::gen_keypair_with_rng(&mut csprng);
                let encapped_key = Kem::encap_with_rng(&pk_recip, None, &mut csprng).unwrap().1;

                let encapped_key_bytes = encapped_key.to_bytes();
                let new_encapped_key =
                    <<Kem as KemTrait>::EncappedKey as Deserializable>::from_bytes(
                        &encapped_key_bytes,
                    )
                    .unwrap();

                assert_eq!(
                    new_encapped_key.to_bytes(),
                    encapped_key.to_bytes(),
                    "encapped key doesn't serialize correctly"
                );
            }
        };
    }

    #[cfg(feature = "mlkem768")]
    test_encap_correctness!(test_encap_correctness_mlkem768, MlKem768);
    #[cfg(feature = "mlkem1024")]
    test_encap_correctness!(test_encap_correctness_mlkem1024, MlKem1024);
    #[cfg(feature = "mlkem768")]
    test_encapped_serialize!(test_encapped_serialize_mlkem768, MlKem768);
    #[cfg(feature = "mlkem1024")]
    test_encapped_serialize!(test_encapped_serialize_mlkem1024, MlKem1024);

    /// Tests that the wire sizes match the constants in draft-ietf-hpke-pq-04 §3
    #[cfg(feature = "mlkem768")]
    #[test]
    fn sizes_match_spec_mlkem768() {
        // ML-KEM-768: KEM_ID=0x0041, Nsecret=32, Nenc=1088, Npk=1184, Nsk=64
        assert_eq!(MlKem768::KEM_ID, 0x0041);
        assert_eq!(<MlKem768 as KemTrait>::PrivateKey::size(), 64);
        assert_eq!(<MlKem768 as KemTrait>::PublicKey::size(), 1184);
        assert_eq!(<MlKem768 as KemTrait>::EncappedKey::size(), 1088);
    }

    /// Tests that the wire sizes match the constants in draft-ietf-hpke-pq-04 §3
    #[cfg(feature = "mlkem1024")]
    #[test]
    fn sizes_match_spec_mlkem1024() {
        // ML-KEM-1024: KEM_ID=0x0042, Nsecret=32, Nenc=1568, Npk=1568, Nsk=64
        assert_eq!(MlKem1024::KEM_ID, 0x0042);
        assert_eq!(<MlKem1024 as KemTrait>::PrivateKey::size(), 64);
        assert_eq!(<MlKem1024 as KemTrait>::PublicKey::size(), 1568);
        assert_eq!(<MlKem1024 as KemTrait>::EncappedKey::size(), 1568);
    }

    /// Tests that DeriveKeyPair is deterministic and that derived keypairs round-trip
    #[cfg(feature = "mlkem768")]
    #[test]
    fn derive_keypair_roundtrip() {
        let ikm = [7u8; 64];
        let (sk_a, pk_a) = MlKem768::derive_keypair(&ikm);
        let (sk_b, pk_b) = MlKem768::derive_keypair(&ikm);
        assert_eq!(sk_a.to_bytes(), sk_b.to_bytes());
        assert_eq!(pk_a.to_bytes(), pk_b.to_bytes());
        // sk_to_pk agrees with the derived public key
        assert_eq!(MlKem768::sk_to_pk(&sk_a).to_bytes(), pk_a.to_bytes());

        let mut csprng = rand::rng();
        let (ss, enc) = MlKem768::encap_with_rng(&pk_a, None, &mut csprng).unwrap();
        let ss_recip = MlKem768::decap(&sk_a, None, &enc).unwrap();
        assert_eq!(ss.0, ss_recip.0);
    }
}
