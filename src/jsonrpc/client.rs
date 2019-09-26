use actix_web::web::post;
use crate::jsonrpc::request::Request;
use crate::jsonrpc::response::Response;
use actix_web::http::header;
use actix_web::client::Client as AcitxClient;
use actix_web::client::ClientBuilder as AcitxClientBuilder;
use failure::Error;
use futures::future::Future;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use actix_web::web;
use awc::error::JsonPayloadError;

pub trait Client {
    fn request_method<T: Serialize, R: 'static>(
        &self,
        method: &str,
        params: T,
        timeout: Duration,
    ) -> Box<dyn Future<Item = R, Error = Error>>
    where
        for<'de> R: Deserialize<'de>,
        // T: std::fmt::Debug,
        R: std::fmt::Debug;
}

pub struct HTTPClient {
    id_counter: Arc<Mutex<RefCell<u64>>>,
    url: String,
}

impl HTTPClient {
    pub fn new(url: &str) -> Self {
        Self {
            id_counter: Arc::new(Mutex::new(RefCell::new(0u64))),
            url: url.to_string(),
        }
    }

    fn next_id(&self) -> u64 {
        let counter = self.id_counter.clone();
        let counter = counter.lock().expect("id error");
        let mut value = counter.borrow_mut();
        *value += 1;
        *value
    }
}

impl Client for HTTPClient {
    fn request_method<T: Serialize, R: 'static>(
        &self,
        method: &str,
        params: T,
        timeout: Duration,
    ) -> Box<dyn Future<Item = R, Error = Error>>
    where
        for<'de> R: Deserialize<'de>,
        // T: std::fmt::Debug,
        R: std::fmt::Debug,
    {
        let payload = Request::new(self.next_id(), method, params);
        //println!("\nweb3 request {:?}", to_string(&payload));
        let actix_client = AcitxClientBuilder::new().timeout(timeout).finish();
        Box::new(
            actix_client.post(&self.url)
                .header(header::CONTENT_TYPE, "application/json")
                .send_json(&payload)
                .then(|response| {
                    if response.is_err() {
                           return response.map_err(move |e| {
                                format_err!("JSONRPC Error {}", e)
                            });
                    }
                    response
                        .json()
                        .from_err()
                        .and_then(move |res: ClientResponse<Response<R>>| {
                            //Response<R>
                            trace!("got web3 response {:#?}", res);
                            let data = res.data.into_result();
                            data.map_err(move |e| {
                                format_err!("JSONRPC Error {}: {}", e.code, e.message)
                            })
                        })
                }),
        )
    }
}
