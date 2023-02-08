// Copyright 2022 Databricks, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Module that defines methods to color click output appropriately
use crossterm::style::{Attribute, Attributes, Color, ContentStyle, StyledContent, Stylize};
use std::collections::HashMap;

pub struct Styles {
    prompt_object_map: HashMap<&'static str, ContentStyle>,
}

macro_rules! style {
    ($style_name:ident, $arg:ident $style_apply:block) => {
        pub fn $style_name<'a>(&self, $arg: &'a str) -> StyledContent<&'a str> $style_apply
    };
}

macro_rules! obj_style {
    ($fg: expr) => {
        ContentStyle {
            foreground_color: Some($fg),
            background_color: None,
            underline_color: None,
            attributes: Attributes::default(),
        }
    };
    ($fg: expr, $attrs: expr) => {
        ContentStyle {
            foreground_color: Some($fg),
            background_color: None,
            underline_color: None,
            attributes: $attrs,
        }
    };
}

lazy_static! {
    static ref BOLD: Attributes = {
        let mut attrs = Attributes::default();
        attrs.set(Attribute::Bold);
        attrs
    };
    static ref NOSTYLE: ContentStyle = ContentStyle::new();
}

impl Styles {
    pub fn new() -> Styles {
        let prompt_object_map = HashMap::from([
            ("Pod", obj_style!(Color::Yellow, *BOLD)),
            ("Crd", obj_style!(Color::Blue, *BOLD)),
            ("Node", obj_style!(Color::Blue, *BOLD)),
            ("DaemonSet", obj_style!(Color::Yellow, *BOLD)),
            ("Deployment", obj_style!(Color::Magenta, *BOLD)),
            ("Service", obj_style!(Color::Cyan, *BOLD)),
            ("ReplicaSet", obj_style!(Color::Green, *BOLD)),
            ("StatefulSet", obj_style!(Color::Green, *BOLD)),
            ("ConfigMap", obj_style!(Color::Magenta, *BOLD)),
            ("Secret", obj_style!(Color::Red, *BOLD)),
            ("CronJob", obj_style!(Color::Green, *BOLD)),
            ("Job", obj_style!(Color::Magenta, *BOLD)),
            ("PersistentVolume", obj_style!(Color::Blue, *BOLD)),
            ("StorageClass", obj_style!(Color::Red, *BOLD)),
            #[cfg(feature = "argorollouts")]
            ("Rollout", obj_style!(Color::Magenta, *BOLD)),
        ]);

        Styles { prompt_object_map }
    }

    pub fn prompt_object<'a>(&self, name: &'a str, type_str: &str) -> StyledContent<&'a str> {
        match self.prompt_object_map.get(type_str) {
            Some(style) => style.apply(name),
            None => NOSTYLE.apply(name),
        }
    }

    // general colors
    style!(success, s {s.dark_green()});
    style!(warning, s {s.dark_yellow()});
    style!(danger,  s {s.dark_red()});

    // prompt colors
    style!(prompt_context,     s {s.red().bold()});
    style!(prompt_namespace,   s {s.green().bold()});
    style!(prompt_range,       s {s.blue()});
    style!(prompt_select_none, s {s.dark_yellow()});

    // config printing colors
    // TODO: Maybe add this
    // style!(config_key, s {s.red()});
    pub fn config_val_string(&self, s: String) -> StyledContent<String> {
        s.yellow()
    }
    style!(config_val, s {s.yellow()});

    // other colors
    pub fn success_color(&self) -> Color {
        Color::DarkGreen
    }
    pub fn warning_color(&self) -> Color {
        Color::DarkYellow
    }
    pub fn danger_color(&self) -> Color {
        Color::DarkRed
    }
    pub fn info_color(&self) -> Color {
        Color::DarkBlue
    }

    pub fn context_table_color(&self) -> Color {
        Color::Red
    }

    // attributes
    style!(bold, s {s.bold()});
}

impl Default for Styles {
    fn default() -> Self {
        Self::new()
    }
}
