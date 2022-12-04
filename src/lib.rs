pub mod token_validator_lib {
    // esta é a declaracao basica de um modulo

    extern crate clap;

    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    //use log::debug;
    //use log::error;
    //use log::warn;
    use clap::Parser;
    use std::collections::BTreeMap;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        pub sub: String,
        pub resource_access: BTreeMap<String, Role>,
        pub preferred_username: String,
        pub given_name: String,
        pub family_name: String,
        pub email_verified: bool,
        pub email: String,
        pub name: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Role {
        pub roles: Vec<String>,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
    pub struct JwtKey {
        pub kid: String,
        pub kty: String,
        pub alg: String,
        pub n: String,
        pub e: String,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
    pub struct JwtKeysCollection {
        #[serde(rename = "keys")]
        pub jwt_keys: Vec<JwtKey>,
    }

    #[derive(Parser, Default, Debug)]
    pub struct ExecutionVars {
        #[clap(short, long)]
        /// Keycloak realm keys endpoint (normally certs endpoint). Also can be set by the env var KEYCLOAK_KEYS_PATH
        pub keycloak_keys_path: Option<String>,

        #[clap(short, long)]
        /// Port this service will listen. Also can be set by the env var SERVICE_PORT
        pub service_port: Option<String>,

        //pub realm_keys_cache: Option<u32>,
        #[clap(short, long)]
        /// Ip / interface that this service will listen. Also can be set by the env var BIND_IP
        pub bind_ip: Option<String>,

        #[clap(short, long)]
        /// Allow keycloak self signed certificates (only for test purposes). Also can be set by the env var DISABLE_CERT_CHECK
        pub disable_cert_check: Option<String>,

        #[clap(short, long)]
        /// number of api workers/threads (default=1)
        pub number_of_workers: Option<usize>,
        //.workers(4)
    }

    pub async fn get_keycloak_public_keys(
        certs_url: String,
        disable_cert_check: String,
    ) -> Result<HashMap<String, JwtKey>, Box<dyn std::error::Error>> {
        //-> Result<String, Error>{ // a declaracao de funcoes e feita dentro do modulo
        //let client = Client::new();

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(disable_cert_check.parse()?)
            .build()
            .unwrap();

        //let response = reqwest::get("https://auth.slaproject.local/realms/sla/protocol/openid-connect/certs/").await;
        let key_array = client
            .get(certs_url)
            //.header(CONTENT_TYPE, "application/json")
            .send()
            .await?
            .json::<JwtKeysCollection>()
            .await?;

        let mut key_map = HashMap::new();
        for element in key_array.jwt_keys.iter() {
            //println!("the value is: {:?}", element);
            key_map.insert(element.kid.clone(), element.clone());
        }

        Ok(key_map)
    }
}
