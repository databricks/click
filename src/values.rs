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

/// Helper functions to deal with Values
use serde_json::value::Value;

use crate::error::KubeError;

use std::borrow::Cow;

pub fn val_str<'a>(pointer: &str, value: &'a Value, default: &'a str) -> Cow<'a, str> {
    match value.pointer(pointer) {
        Some(p) => match p.as_str() {
            Some(s) => s.into(),
            None => default.into(),
        },
        None => default.into(),
    }
}

/// Get the item at specified pointer, assuming it's a Number, and format it as a string
#[allow(dead_code)] // used by features, so without them isn't used
pub fn val_num(pointer: &str, value: &Value, default: &str) -> String {
    match value.pointer(pointer) {
        Some(p) => match p.as_i64() {
            Some(i) => format!("{}", i),
            None => default.into(),
        },
        None => default.into(),
    }
}

/// Get the specified path, or None if doesn't exist
pub fn val_str_opt(pointer: &str, value: &Value) -> Option<String> {
    value
        .pointer(pointer)
        .map(|p| p.as_str().map(|s| s.to_owned()))
        .and_then(|s| s)
}

pub fn val_u64(pointer: &str, value: &Value, default: u64) -> u64 {
    match value.pointer(pointer) {
        Some(p) => match p.as_u64() {
            Some(i) => i,
            None => default,
        },
        None => default,
    }
}

/// Return the count of the number of items in the item at the
/// specified path.  Returns 0 if the the item there isn't an Array or Object
pub fn _val_item_count(pointer: &str, value: &Value) -> usize {
    match value.pointer(pointer) {
        Some(p) => {
            if p.is_array() {
                p.as_array().unwrap().len() // safe, just checked
            } else if p.is_object() {
                p.as_object().unwrap().len() // safe, just checked
            } else {
                0
            }
        }
        None => 0,
    }
}

pub fn _get_val_as<T>(pointer: &str, value: &Value) -> Result<T, KubeError>
where
    for<'de> T: serde::Deserialize<'de>,
{
    match value.pointer(pointer) {
        Some(p) => serde::Deserialize::deserialize(p).map_err(KubeError::from),
        None => Err(KubeError::ParseErr("Can't deserialize".to_owned())),
    }
}
