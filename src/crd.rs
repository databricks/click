// Copyright 2017 Databricks, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// code to deal with discovering and quering endpoints created by crds

use k8s_openapi::{
    apimachinery::pkg::apis::meta::v1::{APIGroup, APIResourceList},
    http::{Request, StatusCode},
    GetAPIVersionsResponse, RequestError, Response, ResponseBody, ResponseError,
};

use crate::{env::Env, error::ClickError};

pub fn get_api_groups(env: &mut Env) -> Result<Vec<APIGroup>, ClickError> {
    let (request, _) = k8s_openapi::get_api_versions()?;
    match env.run_on_context::<_, GetAPIVersionsResponse>(|c| c.read(request))? {
        GetAPIVersionsResponse::Ok(groups) => Ok(groups.groups),
        GetAPIVersionsResponse::Other(_) => Err(ClickError::CommandError(
            "Could not fetch api groups".to_string(),
        )),
    }
}

#[allow(clippy::type_complexity)] // type from k8s_openapi
pub fn get_api_group_resources(
    group_version: &str,
) -> Result<
    (
        Request<Vec<u8>>,
        fn(k8s_openapi::http::StatusCode) -> ResponseBody<GetAPIGroupResourcesResponse>,
    ),
    RequestError,
> {
    let url = format!("/apis/{}", group_version);
    let request = Request::get(url);
    let body = vec![];
    match request.body(body) {
        Ok(request) => Ok((request, ResponseBody::new)),
        Err(err) => Err(RequestError::Http(err)),
    }
}

#[derive(Debug)]
pub enum GetAPIGroupResourcesResponse {
    Ok(APIResourceList),
    Other(Result<Option<serde_json::Value>, serde_json::Error>),
}

impl Response for GetAPIGroupResourcesResponse {
    fn try_from_parts(status_code: StatusCode, buf: &[u8]) -> Result<(Self, usize), ResponseError> {
        match status_code {
            StatusCode::OK => {
                let result = match serde_json::from_slice(buf) {
                    Ok(value) => value,
                    Err(ref err) if err.is_eof() => return Err(ResponseError::NeedMoreData),
                    Err(err) => return Err(ResponseError::Json(err)),
                };
                Ok((GetAPIGroupResourcesResponse::Ok(result), buf.len()))
            }
            _ => {
                let (result, read) = if buf.is_empty() {
                    (Ok(None), 0)
                } else {
                    match crate::serde_json::from_slice(buf) {
                        Ok(value) => (Ok(Some(value)), buf.len()),
                        Err(ref err) if err.is_eof() => return Err(ResponseError::NeedMoreData),
                        Err(err) => (Err(err), 0),
                    }
                };
                Ok((GetAPIGroupResourcesResponse::Other(result), read))
            }
        }
    }
}

#[allow(clippy::type_complexity)] // type from k8s_openapi
pub fn read_namespaced_resource(
    name: &str,
    namespace: &str,
    _type: &str,
    group_version: &str,
) -> Result<
    (
        Request<Vec<u8>>,
        fn(k8s_openapi::http::StatusCode) -> ResponseBody<ReadResourceValueResponse>,
    ),
    RequestError,
> {
    let url = format!(
        "/apis/{}/namespaces/{}/{}/{}",
        group_version, namespace, _type, name
    );
    let request = Request::get(url);
    let body = vec![];
    match request.body(body) {
        Ok(request) => Ok((request, ResponseBody::new)),
        Err(err) => Err(RequestError::Http(err)),
    }
}

#[derive(Debug)]
pub enum ReadResourceValueResponse {
    Ok(serde_json::Value),
    Other(Result<Option<serde_json::Value>, serde_json::Error>),
}

impl Response for ReadResourceValueResponse {
    fn try_from_parts(status_code: StatusCode, buf: &[u8]) -> Result<(Self, usize), ResponseError> {
        match status_code {
            StatusCode::OK => {
                let result = match serde_json::from_slice(buf) {
                    Ok(value) => value,
                    Err(ref err) if err.is_eof() => return Err(ResponseError::NeedMoreData),
                    Err(err) => return Err(ResponseError::Json(err)),
                };
                Ok((ReadResourceValueResponse::Ok(result), buf.len()))
            }
            _ => {
                let (result, read) = if buf.is_empty() {
                    (Ok(None), 0)
                } else {
                    match crate::serde_json::from_slice(buf) {
                        Ok(value) => (Ok(Some(value)), buf.len()),
                        Err(ref err) if err.is_eof() => return Err(ResponseError::NeedMoreData),
                        Err(err) => (Err(err), 0),
                    }
                };
                Ok((ReadResourceValueResponse::Other(result), read))
            }
        }
    }
}
