// SPDX-License-Identifier: Apache-2.0

use crate::coserv::{CoseAlgorithm, CoseKey, CoseKeyOwner, CoseSigner, CoseVerifier};
use corim_rs::CorimError;
use jsonwebkey as jwk;
use std::str::FromStr;

/// Wrapper around [corim_rs::OpensslSigner]
pub struct OpensslSigner(corim_rs::OpensslSigner);

impl CoseKeyOwner for OpensslSigner {
    fn to_cose_key(&self) -> CoseKey {
        self.0.to_cose_key()
    }
}

/// Wrapper around [corim_rs::OpensslSigner]
pub struct OpensslVerifier(corim_rs::OpensslSigner);

impl CoseKeyOwner for OpensslVerifier {
    fn to_cose_key(&self) -> CoseKey {
        self.0.to_cose_key()
    }
}

impl OpensslSigner {
    /// Construct [OpensslSigner] from PEM encoded private key
    pub fn from_pem(key: &str) -> Result<Self, CorimError> {
        Ok(Self(corim_rs::OpensslSigner::private_key_from_pem(
            key.as_bytes(),
        )?))
    }

    /// Construct [OpensslSigner] from JWK encoded private key
    pub fn from_jwk(key: &str) -> Result<Self, CorimError> {
        Ok(Self(corim_rs::OpensslSigner::private_key_from_pem(
            jwk_to_pem(key)?.as_bytes(),
        )?))
    }
}

impl CoseSigner for OpensslSigner {
    fn sign(&self, alg: CoseAlgorithm, data: &[u8]) -> Result<Vec<u8>, CorimError> {
        Ok(self.0.sign(alg, data)?)
    }
}

impl OpensslVerifier {
    /// Construct [OpensslVerifier] from PEM encoded public key
    pub fn from_pem(key: &str) -> Result<Self, CorimError> {
        Ok(Self(corim_rs::OpensslSigner::public_key_from_pem(
            key.as_bytes(),
        )?))
    }

    /// Construct [OpensslVerifier] from JWK encoded public key
    pub fn from_jwk(key: &str) -> Result<Self, CorimError> {
        Ok(Self(corim_rs::OpensslSigner::public_key_from_pem(
            jwk_to_pem(key)?.as_bytes(),
        )?))
    }
}

impl CoseVerifier for OpensslVerifier {
    fn verify_signature(
        &self,
        alg: CoseAlgorithm,
        sig: &[u8],
        data: &[u8],
    ) -> Result<(), CorimError> {
        Ok(self.0.verify_signature(alg, sig, data)?)
    }
}

fn jwk_to_pem(key: &str) -> Result<String, CorimError> {
    jwk::JsonWebKey::from_str(key)
        .map_err(CorimError::custom)?
        .key
        .try_to_pem()
        .map_err(CorimError::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coserv::Coserv;

    const COSERV: [u8; 158] = [
        0xa3, 0x00, 0x63, 0x66, 0x6f, 0x6f, 0x01, 0xa4, 0x00, 0x02, 0x01, 0xa1, 0x01, 0x82, 0x81,
        0xd9, 0x02, 0x30, 0x43, 0x00, 0x01, 0x02, 0x81, 0xd9, 0x02, 0x30, 0x43, 0x01, 0x02, 0x03,
        0x02, 0xc0, 0x78, 0x19, 0x32, 0x30, 0x32, 0x35, 0x2d, 0x31, 0x30, 0x2d, 0x32, 0x37, 0x54,
        0x31, 0x39, 0x3a, 0x31, 0x31, 0x3a, 0x33, 0x30, 0x2b, 0x30, 0x35, 0x3a, 0x33, 0x30, 0x03,
        0x01, 0x02, 0xa2, 0x00, 0x82, 0xa2, 0x01, 0x81, 0xd9, 0x02, 0x30, 0x42, 0x00, 0x01, 0x02,
        0x82, 0xbf, 0x01, 0xd9, 0x02, 0x30, 0x43, 0x00, 0x01, 0x02, 0xff, 0x81, 0xbf, 0x01, 0xbf,
        0x0b, 0x63, 0x66, 0x6f, 0x6f, 0xff, 0xff, 0xa2, 0x01, 0x81, 0xd9, 0x02, 0x30, 0x42, 0x00,
        0x01, 0x02, 0x82, 0xbf, 0x01, 0xd9, 0x02, 0x30, 0x43, 0x01, 0x02, 0x03, 0xff, 0x81, 0xbf,
        0x01, 0xbf, 0x0b, 0x63, 0x66, 0x6f, 0x6f, 0xff, 0xff, 0x0a, 0xc0, 0x78, 0x19, 0x32, 0x30,
        0x32, 0x35, 0x2d, 0x31, 0x31, 0x2d, 0x32, 0x31, 0x54, 0x31, 0x36, 0x3a, 0x30, 0x38, 0x3a,
        0x35, 0x36, 0x2b, 0x30, 0x35, 0x3a, 0x33, 0x30,
    ];

    const PRIV_PEM: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGcXyKllYJ/Ll0jUI9LfK/7uokvFibisW5lM8DZaRO+toAoGCCqGSM49
AwEHoUQDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpoeCJsPxG2h
zMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
-----END EC PRIVATE KEY-----
"#;

    const PUB_PEM: &str = r#"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4Q
hU80ttXzJ7waTpoeCJsPxG2hzMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
-----END PUBLIC KEY-----
"#;

    const PRIV_JWK: &str = r#"
{
  "kty": "EC",
  "crv": "P-256",
  "alg": "ES256",
  "d": "ZxfIqWVgn8uXSNQj0t8r_u6iS8WJuKxbmUzwNlpE760",
  "x": "_gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpo",
  "y": "HgibD8RtoczLlJBzDi62cTacMR9NOL8mh6RfU2E3lwk"
}
"#;

    const PUB_JWK: &str = r#"
{
  "kty": "EC",
  "crv": "P-256",
  "alg": "ES256",
  "x": "_gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpo",
  "y": "HgibD8RtoczLlJBzDi62cTacMR9NOL8mh6RfU2E3lwk"
}
"#;

    #[test]
    fn test_sign_verify_pem() {
        let resp = Coserv::from_cbor(&COSERV[..]).unwrap();
        let signer = OpensslSigner::from_pem(PRIV_PEM).unwrap();
        let signed_resp = resp.sign(&signer, CoseAlgorithm::ES256).unwrap();

        let verifier = OpensslVerifier::from_pem(PUB_PEM).unwrap();
        let res = Coserv::verify_and_extract(&verifier, signed_resp.as_slice());
        assert!(res.is_ok());
    }

    #[test]
    fn test_sign_verify_jwk() {
        let resp = Coserv::from_cbor(&COSERV[..]).unwrap();
        let signer = OpensslSigner::from_jwk(PRIV_JWK).unwrap();
        let signed_resp = resp.sign(&signer, CoseAlgorithm::ES256).unwrap();

        let verifier = OpensslVerifier::from_jwk(PUB_JWK).unwrap();
        let res = Coserv::verify_and_extract(&verifier, signed_resp.as_slice());
        assert!(res.is_ok());
    }
}
