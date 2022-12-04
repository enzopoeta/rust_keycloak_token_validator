use actix_web::middleware::Compress;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use cached::proc_macro::cached;
use env_logger::Env;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
//use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
//use log::debug;
//use log::error;
use log::{error, info};
//use log::warn;
use clap::Parser;
use once_cell::sync::OnceCell;
use rust_keycloak_token_validator::token_validator_lib::get_keycloak_public_keys;
use rust_keycloak_token_validator::token_validator_lib::{Claims, ExecutionVars, JwtKey};
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;

const BIND_IP: &str = "BIND_IP";
const KEYCLOAK_KEYS_PATH: &str = "KEYCLOAK_KEYS_PATH";
const SERVICE_PORT: &str = "SERVICE_PORT";
const DISABLE_CERT_CHECK: &str = "DISABLE_CERT_CHECK";
const NUMBER_OF_WORKERS: &str = "NUMBER_OF_WORKERS";

static KEYCLOAK_CERTS_URL: OnceCell<Mutex<String>> = OnceCell::new();
static DISABLE_CERT_CHECK_VAL: OnceCell<Mutex<String>> = OnceCell::new();

#[cached(size = 1, time = 30)]
async fn get_realm_keys() -> HashMap<String, JwtKey> {
    info!("Recuperando as chaves do realm");

    let certs_url = ensure_certs_url().lock().unwrap().clone();
    let disable_certs_check = ensure_disable_cert_check().lock().unwrap().clone();

    let result = match get_keycloak_public_keys(certs_url, disable_certs_check).await {
        Ok(res) => res,
        Err(err) => {
            error!("Erro ao recuperar as chaves do realm keycloak -> {}", err);
            HashMap::new()
        }
    };

    result
}

async fn token_check(token: &String) -> Result<TokenData<Claims>, Box<dyn std::error::Error>> {
    // recuperando as keys do realm do keycloak escolhido
    let realm_keys = get_realm_keys().await;
    if realm_keys.is_empty() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Problemas ao recuperar as chaves do realm",
        )));
    }

    // decodando o header do token para recuperar o kid
    let token_header = decode_header(&token)?;

    // recuperando o kid do token
    let token_kid = token_header.kid.ok_or_else(|| {
        return std::io::Error::new(
            std::io::ErrorKind::Other,
            "nao foi possivel recuperar o kid no header do token",
        );
    })?;

    // verificando se o kid do token consta da lista de chaves do realms
    // recuperando a public key do realm baseado no kid do token
    let key_components = realm_keys.get(&token_kid).ok_or_else(|| {
        return std::io::Error::new(
            std::io::ErrorKind::Other,
            "kid do token nao encontrado la lista de chaves do realm",
        );
    })?;

    // criando o objeto de chave da crate jsonwebtoken
    let decoding_key = DecodingKey::from_rsa_components(&key_components.n, &key_components.e)?;

    // decodificando o token com a chave para obter as claims
    let claims = decode::<Claims>(&token, &decoding_key, &Validation::new(Algorithm::RS256))?;
    println!(" token data -> {:?}", claims);
    Ok(claims)
}

async fn validate_token(req: HttpRequest) -> impl Responder {
    let req_headers = req.headers();

    let basic_auth_header = req_headers.get("Authorization");
    match basic_auth_header {
        Some(header) => {
            let basic_auth: &str = header.to_str().unwrap();
            if !basic_auth.starts_with("Bearer") {
                HttpResponse::BadRequest().body("Invalid Authorization header value !")
            } else {
                let jwt_token: String = str::replace(&basic_auth, "Bearer ", "");

                // format!("{:?}", token_check(&jwt_token).await)
                match token_check(&jwt_token).await {
                    Ok(token_data) => {
                        //HttpResponse::Ok().body(serde_json::to_string(&token_data.claims).unwrap())
                        HttpResponse::Ok().json(web::Json(&token_data.claims))
                        //Ok(web::Json(&token_data.claims))
                    }
                    Err(e) => {
                        if format!("{:?}", e).contains("ExpiredSignature") {
                            return HttpResponse::Unauthorized().body(format!("{:?}", e));
                        }
                        if format!("{:?}", e).contains("Error(Base64(") {
                            return HttpResponse::BadRequest().body(format!("{:?}", e));
                        }

                        HttpResponse::InternalServerError().body(format!("{:?}", e))
                    } // _ => HttpResponse::InternalServerError().body("No claims found on token"),
                }
            }
        }
        None => HttpResponse::BadRequest().body("Authorization header not found"),
    }
}

async fn get_execution_vars() -> ExecutionVars {
    // tentando preencher as variaveis de execucao a partir dos parametros de linha de comando
    let mut exec_vars = ExecutionVars::parse();

    // se tivermos variaveis de ambiente com nossos parametros elas terao precedencia sobre os parametros
    // de linha de comando
    exec_vars.bind_ip = match env::var(BIND_IP) {
        Ok(val) => Some(val),
        _ => exec_vars.bind_ip,
    };

    exec_vars.number_of_workers = match env::var(NUMBER_OF_WORKERS) {
        Ok(val) => {
            let result = match val.parse::<usize>() {
                Ok(ok_val) => ok_val,
                Err(_) => {
                    error!("Non number on number of workers parameter setting default(1)");
                    1
                }
            };

            Some(result)
        }
        _ => exec_vars.number_of_workers,
    };

    exec_vars.keycloak_keys_path = match env::var(KEYCLOAK_KEYS_PATH) {
        Ok(val) => Some(val),
        _ => exec_vars.keycloak_keys_path,
    };

    exec_vars.disable_cert_check = match env::var(DISABLE_CERT_CHECK) {
        Ok(val) => Some(val.parse().unwrap()),
        _ => exec_vars.disable_cert_check,
    };

    exec_vars.service_port = match env::var(SERVICE_PORT) {
        Ok(val) => Some(val),
        _ => exec_vars.service_port,
    };

    exec_vars
}

fn ensure_certs_url() -> &'static Mutex<String> {
    KEYCLOAK_CERTS_URL.get_or_init(|| Mutex::new(String::new()))
}

fn ensure_disable_cert_check() -> &'static Mutex<String> {
    DISABLE_CERT_CHECK_VAL.get_or_init(|| Mutex::new(String::new()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    //env_logger::from_env(Env::default().default_filter_or("debug")).init();
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    // lendo variaveis de execucao
    let mut e_vars = get_execution_vars().await;

    // verificando se os valores obrigatorios estao presentes e fazendo algumas validacoes de valores default
    if None == e_vars.keycloak_keys_path {
        info!("Keycloak certs endpoint not defined use --help for more details");
        return Ok(());
    }

    if None == e_vars.bind_ip {
        e_vars.bind_ip = Some("127.0.0.1".to_string());
    }

    if None == e_vars.service_port {
        e_vars.service_port = Some("8000".to_string());
    }

    if None == e_vars.disable_cert_check {
        e_vars.disable_cert_check = Some("false".to_string());
    }

    if None == e_vars.number_of_workers {
        e_vars.number_of_workers = Some(1);
    }

    println!("{:?}", e_vars);

    // seetando a variavel global com o thread safe para a URL do keycloak
    *ensure_certs_url().lock().unwrap() = e_vars.keycloak_keys_path.unwrap();

    // seetando a variavel global com o thread safe para a URL do keycloak
    *ensure_disable_cert_check().lock().unwrap() = e_vars.disable_cert_check.unwrap();

    //bind do server
    let server_url = format!(
        "{}:{}",
        e_vars.bind_ip.unwrap(),
        e_vars.service_port.unwrap()
    );

    //println!("{:?}", args);

    //let result = get_keycloak_public_keys().await;

    //println!("{:?}", result.unwrap());

    // carregando certificado ssl
    // to create a self-signed temporary cert for testing:
    // `openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'`

    //   let mut ssl_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    //   ssl_builder
    //       .set_private_key_file("key.pem", SslFiletype::PEM)
    //       .unwrap();
    //   ssl_builder.set_certificate_chain_file("cert.pem").unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default()) //middleware de log
            .wrap(Logger::new("%a %{User-Agent}i")) ////middleware de log
            .wrap(Compress::default()) // middleware de compressao
            .route("/validatetoken", web::get().to(validate_token))
    })
    .bind(server_url)?
    .workers(e_vars.number_of_workers.unwrap())
    .run()
    .await
}
