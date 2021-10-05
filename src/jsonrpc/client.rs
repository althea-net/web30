use crate::jsonrpc::error::Web3Error;
use crate::jsonrpc::request::Request;
use crate::jsonrpc::response::Response;
use crate::mem::get_buffer_size;
use awc::http::header;
use awc::Client;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct HttpClient {
    id_counter: Arc<Mutex<RefCell<u64>>>,
    url: String,
    client: Client,
}

impl HttpClient {
    pub fn new(url: &str) -> Self {
        Self {
            id_counter: Arc::new(Mutex::new(RefCell::new(0u64))),
            url: url.to_string(),
            client: Client::default(),
        }
    }

    fn next_id(&self) -> u64 {
        let counter = self.id_counter.clone();
        let counter = counter.lock().expect("id error");
        let mut value = counter.borrow_mut();
        *value += 1;
        *value
    }

    pub async fn request_method<T: Serialize, R: 'static>(
        &self,
        method: &str,
        params: T,
        timeout: Duration,
    ) -> Result<R, Web3Error>
    where
        for<'de> R: Deserialize<'de>,
        T: std::fmt::Debug,
        R: std::fmt::Debug,
    {
        let payload = Request::new(self.next_id(), method, params);
        let res = self
            .client
            .post(&self.url)
            .append_header((header::CONTENT_TYPE, "application/json"))
            .timeout(timeout)
            .send_json(&payload)
            .await;
        let mut res = match res {
            Ok(val) => val,
            Err(e) => return Err(Web3Error::FailedToSend(e)),
        };

        trace!("response headers {:?}", res.headers());

        let request_size_limit = get_buffer_size();
        trace!("using buffer size of {}", request_size_limit);

        // Manual debugging
        // The `Response` struct has a `ResponseData` enum flattened into it in order to match the
        // error or result fields that the json can have. Unfortunately, this breaks serde's error
        // reporting, so this code uses a dummy struct to better analyze deserialization errors.
        /*
        // note: needs actix-http in Cargo.toml
        dbg!(&res);
        use actix_http::HttpMessage;
        let mut stream = res.take_payload();
        use futures::prelude::stream::StreamExt;
        println!("raw response:");
        let mut s = String::new();
        while let Some(x) = stream.next().await {
            s += &String::from_utf8(x.unwrap().into_iter().collect()).unwrap();
        }
        for c in s.chars() {
            print!("{}", c);
            if c == ',' {
                println!();
            }
        }
        println!();
        #[derive(Serialize, Deserialize, Debug, Clone)]
        pub struct DummyResponse<R> {
            pub id: serde_json::Value,
            pub jsonrpc: String,
            pub result: R,
        }
        let _tmp: Result<DummyResponse<R>, _> = serde_json::from_str(&s);
        dbg!(&_tmp);
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        // use this response instead when uncommented
        let response: Result<Response<R>, _> = serde_json::from_str(&s);
        */

        let response: Result<Response<R>, _> = res.json::<Response<R>>().limit(request_size_limit).await;
        let decoded: Response<R> = match response {
            Ok(val) => val,
            Err(e) => {
                return Err(Web3Error::BadResponse(format!(
                    "Size Limit {} Web3 Error {}",
                    request_size_limit, e
                )))
            }
        };
        //Response<R>
        trace!("got web3 response {:#?}", decoded);
        let data = decoded.data.into_result();
        match data {
            Ok(r) => Ok(r),
            Err(e) => Err(Web3Error::JsonRpcError {
                code: e.code,
                message: e.message,
                data: format!("{:?}", e.data),
            }),
        }
    }
}
