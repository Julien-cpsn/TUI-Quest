extern crate jsonwebtoken as jwt;
use std::collections::HashMap;

use jwt::{Algorithm, encode, EncodingKey, Header};
use serde_json::Value;

pub enum KeyFormat {
    PEM,
    DER,
    B64,
    TEXT
}

pub fn generate_jwt_token(claims: &str, private_key_string: &str, kid: Option<String>, alg: Option<Algorithm>, key_format: Option<KeyFormat>) -> Result<String, Box<dyn std::error::Error>> {
    let algorithm = match alg {
        Some(alg) => alg,
        None => Algorithm::HS256
    };

    let encoding_key = match alg {
        Some(Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512) => {
            match key_format {
                Some(KeyFormat::PEM) => EncodingKey::from_rsa_pem(private_key_string.as_ref()).unwrap(),
                Some(KeyFormat::DER) => EncodingKey::from_rsa_der(private_key_string.as_ref()),
                _ => return Err("Invalid key format for RSA/PS algorithm")?
            }
        },
        Some(Algorithm::ES256 | Algorithm::ES384) => {
            match key_format {
                Some(KeyFormat::PEM) => EncodingKey::from_ec_pem(private_key_string.as_ref()).unwrap(),
                Some(KeyFormat::DER) => EncodingKey::from_ec_der(private_key_string.as_ref()),
                _ => return Err("Invalid key format for ES algorithm")?
            }
        },
        Some(Algorithm::EdDSA) => {
            match key_format {
                Some(KeyFormat::PEM) => EncodingKey::from_ed_pem(private_key_string.as_ref()).unwrap(),
                Some(KeyFormat::DER) => EncodingKey::from_ed_der(private_key_string.as_ref()),
                _ => return Err("Invalid key format for EdDSA algorithm")?
            }
        },
        _ => {
            match key_format {
                Some(KeyFormat::B64) => EncodingKey::from_base64_secret(private_key_string.as_ref()).unwrap(),
                Some(KeyFormat::TEXT) => EncodingKey::from_secret(private_key_string.as_ref()),
                _ => return Err("Invalid key format for HMAC algorithm")?
            }
        }
    };

    let mut header = Header::new(algorithm);
    header.kid = kid;

    let payload: HashMap<String, Value> = serde_json::from_str(claims).unwrap();

    let token = encode(&header, &payload, &encoding_key);
    match token {
        Ok(token) => Ok(token),
        Err(e) => Err(Box::new(e))
    }
}
