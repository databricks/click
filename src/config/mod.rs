// Copyright 2021 Databricks, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod click;
mod kube;
mod kubefile;

pub use self::click::Alias;
pub use self::click::ClickConfig;
pub use self::click::CompletionType;
pub use self::click::EditMode;

#[cfg(test)]
pub use self::kube::tests::get_test_config;
pub use self::kube::Config;

pub use self::kubefile::AuthProvider;
pub use self::kubefile::ContextConf;
pub use self::kubefile::{ExecAuth, ExecProvider};
