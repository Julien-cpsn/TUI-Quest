use boa_engine::{Context, JsError, JsResult, JsString, JsValue};
use jsonwebtoken::Algorithm;

use super::jwt::{generate_jwt_token, KeyFormat};

fn build_arg_extractor<'a>(args: &'a [JsValue]) -> Box<dyn Fn(usize) -> String + 'a> {
    Box::new(move |index| args.get(index).unwrap().as_string().unwrap().to_std_string().unwrap())
}

pub fn generate_signed_jwt(_this: &JsValue, args: &[JsValue], _ctx: &mut Context) -> JsResult<JsValue> {
    let arg_extractor = build_arg_extractor(args);

    let claims = arg_extractor(0);
    let private_key_string = arg_extractor(1);
    let kid = arg_extractor(2);
    let alg = arg_extractor(3);
    let raw_key_format = arg_extractor(4);

    let rust_alg = match alg.as_str() {
        "HS256" => Some(Algorithm::HS256),
        "HS384" => Some(Algorithm::HS384),
        "HS512" => Some(Algorithm::HS512),
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        _ => None
    };

    let key_format = match raw_key_format.as_str() {
        "pem" => Some(KeyFormat::PEM),
        "der" => Some(KeyFormat::DER),
        "b64" => Some(KeyFormat::B64),
        "text" => Some(KeyFormat::TEXT),
        _ => None
    };

    let token = generate_jwt_token(&claims, &private_key_string, Some(kid), rust_alg, key_format);
    match token {
        Ok(token) => Ok(JsValue::String(JsString::from(token))),
        Err(e) => Err(JsError::from_opaque(JsValue::String(JsString::from(format!("Error in generate_signed_jwt: {}", e.to_string())))))
    }
}
