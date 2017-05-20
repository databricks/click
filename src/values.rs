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

pub fn val_str(pointer: &str, value: &Value, default: &str) -> String {
    match value.pointer(pointer) {
        Some(p) => match p.as_str() {
            Some(s) => s.to_owned(),
            None => default.to_owned()
        },
        None => default.to_owned()
    }
}

/// Get the specified path, or None if doesn't exist
pub fn val_str_opt(pointer: &str, value: &Value) -> Option<String> {
    value.pointer(pointer).map(|p| {
        p.as_str().map(|s| {
            s.to_owned()
        })
    }).and_then(|s| s)
}

pub fn val_u64(pointer: &str, value: &Value, default: u64) -> u64 {
    match value.pointer(pointer) {
        Some(p) => match p.as_u64() {
            Some(i) => i,
            None => default
        },
        None => default
    }
}
