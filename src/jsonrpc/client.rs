use crate::jsonrpc::error::Web3Error;
use crate::jsonrpc::request::Request;
use crate::jsonrpc::response::Response;
use crate::mem::get_buffer_size;
use reqwest::{header, Client, Method};
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
            url: url.into(),
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
        R: std::fmt::Debug,
    {
        let payload = Request::new(self.next_id(), method, params);

        let res = self
            .client
            .request(Method::POST, &self.url)
            .header(header::CONTENT_TYPE, "application/json")
            .timeout(timeout)
            .json(&payload)
            .send()
            .await?;

        trace!("response headers {:?}", res.headers());

        let request_size_limit = get_buffer_size();
        trace!("using buffer size of {}", request_size_limit);

        let response_content_length = match res.content_length() {
            Some(v) => v as usize,
            None => request_size_limit + 1, // Just to protect ourselves from a malicious response
        };

        if response_content_length > request_size_limit {
            return Err(Web3Error::BadResponse(format!(
                "Size Limit {} Web3 Error",
                request_size_limit
            )));
        }

        let data: Response<R> = res.json().await?;
        trace!("got web3 response {:#?}", data);

        Ok(data.result)
    }
}
