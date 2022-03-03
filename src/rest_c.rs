use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
};

use crate::{http, rest::Format, Rest};

use reqwest::Method;

#[no_mangle]
pub extern "C" fn new_rest_client_with_key(key: *const c_char) -> *mut Rest {
    let key = unsafe { CStr::from_ptr(key) };
    let key = key.to_str().unwrap();
    Box::into_raw(Box::new(Rest::from(key)))
}

#[no_mangle]
pub unsafe extern "C" fn free_rest_client(client: *mut Rest) {
    if !client.is_null() {
        drop(Box::from_raw(client));
    }
}

#[no_mangle]
#[tokio::main]
pub async unsafe extern "C" fn rest_client_time(client: *mut Rest) -> i64 {
    assert!(!client.is_null());
    // TODO: error handling
    let client = &*client;
    if let Ok(time) = client.time().await {
        time.timestamp()
    } else {
        0
    }
}

pub struct RequestBuilder {
    inner: Option<http::RequestBuilder>,
}

pub struct RequestResponse {
    inner: Option<http::Response>,
}

#[repr(C)]
#[allow(dead_code)]
pub enum RequestMethod {
    Options,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Trace,
    Connect,
    Patch,
}
impl RequestMethod {
    fn to_method(&self) -> Method {
        match self {
            RequestMethod::Options => Method::OPTIONS,
            RequestMethod::Get => Method::GET,
            RequestMethod::Post => Method::POST,
            RequestMethod::Put => Method::PUT,
            RequestMethod::Delete => Method::DELETE,
            RequestMethod::Head => Method::HEAD,
            RequestMethod::Trace => Method::TRACE,
            RequestMethod::Connect => Method::CONNECT,
            RequestMethod::Patch => Method::PATCH,
        }
    }
}

#[repr(C)]
#[allow(dead_code)]
pub enum RequestFormat {
    MessagePack,
    JSON,
}
impl RequestFormat {
    fn to_format(&self) -> Format {
        match self {
            RequestFormat::MessagePack => Format::MessagePack,
            RequestFormat::JSON => Format::JSON,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rest_client_request_builder(
    client: *mut Rest,
    method: RequestMethod,
    path: *const c_char,
) -> *mut RequestBuilder {
    assert!(!client.is_null());
    let client = &*client;
    let path = CStr::from_ptr(path).to_str().unwrap();
    let builder = client.request(method.to_method(), path);
    return Box::into_raw(Box::new(RequestBuilder {
        inner: Some(builder),
    }));
}

#[no_mangle]
pub unsafe extern "C" fn rest_client_request_builder_set_format(
    builder: *mut RequestBuilder,
    format: RequestFormat,
) -> bool {
    assert!(!builder.is_null());
    let request_builder = (*builder).inner.take().unwrap();
    let request_builder = request_builder.format(format.to_format());
    (*builder).inner = Some(request_builder);
    true
}

#[no_mangle]
#[tokio::main]
pub async unsafe extern "C" fn rest_client_request_builder_send(
    builder: *mut RequestBuilder,
) -> *mut RequestResponse {
    assert!(!builder.is_null());
    let builder = (*builder).inner.take().unwrap();
    let request = builder.send();
    if let Ok(response) = request.await {
        Box::into_raw(Box::new(RequestResponse {
            inner: Some(response),
        }))
    } else {
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn free_rest_client_request_builder(builder: *mut RequestBuilder) {
    if !builder.is_null() {
        drop(Box::from_raw(builder));
    }
}

#[no_mangle]
#[tokio::main]
pub async unsafe extern "C" fn rest_client_response_body_as_text(
    response: *mut RequestResponse,
) -> *mut c_char {
    assert!(!response.is_null());
    let response = (*response).inner.take().unwrap();
    let body: String = response.body().await.unwrap(); // TODO: panicking here, not sure why
    let body = CString::new(body).unwrap();
    body.into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(input: *mut c_char) {
    unsafe {
        drop(CString::from_raw(input));
    }
}

#[no_mangle]
pub unsafe extern "C" fn free_rest_client_request_response(response: *mut RequestResponse) {
    if !response.is_null() {
        drop(Box::from_raw(response));
    }
}
