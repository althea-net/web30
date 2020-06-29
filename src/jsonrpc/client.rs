use crate::jsonrpc::request::Request;
use crate::jsonrpc::response::Response;
use actix_web::client::Client;
use actix_web::http::header;
use failure::Error;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct HTTPClient {
    id_counter: Arc<Mutex<RefCell<u64>>>,
    url: String,
    client: Client,
}

impl HTTPClient {
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
        request_size_limit: Option<usize>,
    ) -> Result<R, Error>
    where
        for<'de> R: Deserialize<'de>,
        // T: std::fmt::Debug,
        R: std::fmt::Debug,
    {
        // the payload size limit for this request, almost everything
        // will set this to None, and get the default 64k, but some requests
        // need bigger buffers (like full block requests)
        let limit = match request_size_limit {
            Some(val) => val,
            None => 65536,
        };
        let payload = Request::new(self.next_id(), method, params);
        let res = self
            .client
            .post(&self.url)
            .header(header::CONTENT_TYPE, "application/json")
            .timeout(timeout)
            .send_json(&payload)
            .await;
        let mut res = match res {
            Ok(val) => val,
            Err(e) => bail!("Failed sending web3 request with {:?}", e),
        };
        let res: Response<R> = match res.json().limit(limit).await {
            Ok(val) => val,
            Err(e) => bail!("Got unexpected web3 response {:?}", e),
        };
        //Response<R>
        trace!("got web3 response {:#?}", res);
        let data = res.data.into_result();
        data.map_err(move |e| format_err!("JSONRPC Error {}: {}", e.code, e.message))
    }
}
