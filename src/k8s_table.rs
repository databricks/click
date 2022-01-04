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

// Code to deal with the k8s table api:
// https://kubernetes.io/docs/reference/using-api/api-concepts/#receiving-resources-as-tables

use k8s_openapi::{
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
    http::{Request, StatusCode},
    RequestError, Response, ResponseBody, ResponseError,
};
use serde::Deserializer;
use serde_json::Value;

use crate::{
    kobj::{KObj, ObjType},
    output::ClickWriter,
    table::CellSpec,
};

#[derive(Deserialize, Debug)]
#[allow(dead_code)] // needed since we deserialze these fields from k8s
pub struct ColumnDefintion {
    name: String,
    #[serde(rename = "type")]
    _type: String, // TODO: enum?
    format: String, // TODO: Enum?
    description: String,
    priority: i32,
}

#[derive(Debug)]
pub struct Row {
    cells: Vec<Value>,
    metadata: ObjectMeta,
}

// we implement this ourselves to factor out the object->metadata link
impl<'de> serde::Deserialize<'de> for Row {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct FullRow {
            cells: Vec<Value>,
            object: Object,
        }

        #[derive(Deserialize)]
        struct Object {
            metadata: ObjectMeta,
        }

        let nested = FullRow::deserialize(deserializer)?;

        Ok(Row {
            cells: nested.cells,
            metadata: nested.object.metadata,
        })
    }
}

#[derive(Deserialize, Debug)]
pub struct K8sTable {
    #[serde(rename = "columnDefinitions")]
    column_definitions: Vec<ColumnDefintion>,
    rows: Vec<Row>,
}

impl K8sTable {
    pub fn print_to(
        &self,
        show_namespace: bool,
        _type: &str,
        group_version: &str,
        writer: &mut ClickWriter,
    ) -> Vec<KObj> {
        let mut titles: Vec<prettytable::Cell> = vec![prettytable::Cell::new("####")];
        if show_namespace {
            titles.push(prettytable::Cell::new("Namespace"));
        }
        for col_def in self.column_definitions.iter() {
            titles.push(prettytable::Cell::new(&col_def.name));
        }
        let mut rows = vec![];
        let mut kobjs = vec![];
        for row in self.rows.iter() {
            let mut cell_spec_row = vec![CellSpec::new_index()];
            if show_namespace {
                cell_spec_row.push(row.metadata.namespace.as_deref().into());
            }
            for cell in row.cells.iter() {
                if cell.is_string() {
                    // this way doesn't add ""s around the value
                    cell_spec_row.push(cell.as_str().into());
                } else {
                    cell_spec_row.push(cell.to_string().into());
                }
            }
            rows.push(cell_spec_row);
            kobjs.push(KObj {
                name: row.metadata.name.as_ref().unwrap().clone(),
                namespace: row.metadata.namespace.clone(),
                typ: ObjType::Crd {
                    _type: _type.to_string(),
                    group_version: group_version.to_string(),
                },
            });
        }
        crate::table::print_table(prettytable::Row::new(titles), rows, writer);
        kobjs
    }
}

/// The common response type for all table API operations.
#[derive(Debug)]
pub enum GetTableResponse {
    Ok(K8sTable),
    Other(Result<Option<serde_json::Value>, serde_json::Error>),
}

impl Response for GetTableResponse {
    fn try_from_parts(status_code: StatusCode, buf: &[u8]) -> Result<(Self, usize), ResponseError> {
        match status_code {
            StatusCode::OK => {
                let result = match serde_json::from_slice(buf) {
                    Ok(value) => value,
                    Err(ref err) if err.is_eof() => return Err(ResponseError::NeedMoreData),
                    Err(err) => return Err(ResponseError::Json(err)),
                };
                Ok((GetTableResponse::Ok(result), buf.len()))
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
                Ok((GetTableResponse::Other(result), read))
            }
        }
    }
}

#[allow(clippy::type_complexity)] // type from k8s_openapi
pub fn get_k8s_table(
    url: &str,
) -> Result<
    (
        Request<Vec<u8>>,
        fn(StatusCode) -> ResponseBody<GetTableResponse>,
    ),
    RequestError,
> {
    let request = Request::get(url).header(
        k8s_openapi::http::header::ACCEPT,
        "application/json;as=Table;g=meta.k8s.io;v=v1beta1",
    );
    let body = vec![];
    match request.body(body) {
        Ok(request) => Ok((request, ResponseBody::new)),
        Err(err) => Err(RequestError::Http(err)),
    }
}
