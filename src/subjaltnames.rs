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

use ring::der;
use untrusted::{Input, Reader};
use webpki;

use std::borrow::Cow;
use std::mem;

#[derive(Debug, PartialEq)]
enum Object {
    KeyUsage,
    ExtendedKeyUsage,
    BasicConstraints,
    SubjAltNames,
}

// This is gross, but we make our own DNSNameRef, to avoid webpki trying to validate it, and then
// unsafe transmute it to the webpki one.
#[derive(Clone, Copy)]
pub struct DNSNameRef<'a>(Input<'a>);

impl<'a> DNSNameRef<'a> {
    pub fn get_webpki_ref(input: Input<'a>) -> webpki::DNSNameRef<'a> {
        let internal = DNSNameRef(input);
        unsafe { mem::transmute(internal) }
    }
}

// This enum and the general_name function are taken and modified from the webpki crate:
// https://github.com/briansmith/webpki (see names.rs)
#[derive(Clone, Copy, Debug)]
enum GeneralName<'a> {
    DNSName(Input<'a>),
    IPAddress(Input<'a>),
}

fn general_name<'a>(input: &mut Reader<'a>) -> Result<GeneralName<'a>, ()> {
    use ring::der::CONTEXT_SPECIFIC;
    const DNS_NAME_TAG: u8 = CONTEXT_SPECIFIC | 2;
    const IP_ADDRESS_TAG: u8 = CONTEXT_SPECIFIC | 7;

    let tv = der::read_tag_and_get_value(input);
    if tv.is_err() {
        return Err(());
    }
    let (tag, value) = tv.unwrap();
    let name = match tag {
        DNS_NAME_TAG => GeneralName::DNSName(value),
        IP_ADDRESS_TAG => GeneralName::IPAddress(value),
        _ => return Err(()),
    };
    Ok(name)
}

fn obj_to_obj(object: Input<'_>) -> Option<Object> {
    let slice = object.as_slice_less_safe();
    if slice[0] != 85 || slice[1] != 29 {
        None
    } else {
        match slice[2] {
            15 => Some(Object::KeyUsage),
            17 => Some(Object::SubjAltNames),
            19 => Some(Object::BasicConstraints),
            37 => Some(Object::ExtendedKeyUsage),
            _ => None,
        }
    }
}

fn tag_to_tag(tag: u8) -> der::Tag {
    match tag {
        0x01 => der::Tag::Boolean,
        0x02 => der::Tag::Integer,
        0x03 => der::Tag::BitString,
        0x04 => der::Tag::OctetString,
        0x05 => der::Tag::Null,
        0x06 => der::Tag::OID,

        0x13 => der::Tag::BitString,

        0x30 => der::Tag::Sequence,
        0x31 => der::Tag::Sequence,
        0x17 => der::Tag::UTCTime,
        0x18 => der::Tag::GeneralizedTime,

        0xA0 => der::Tag::ContextSpecificConstructed0,
        0xA1 => der::Tag::ContextSpecificConstructed1,
        0xA3 => der::Tag::ContextSpecificConstructed3,
        _ => der::Tag::Null,
    }
}

fn recurse_reader<'a>(reader: &mut Reader<'a>, vec: &mut Vec<SubjAltName<'a>>) {
    let mut is_subj_alt = false;
    while let Ok((tag, rest)) = der::read_tag_and_get_value(reader) {
        match tag_to_tag(tag) {
            der::Tag::Sequence | der::Tag::ContextSpecificConstructed3 => {
                let mut inner_reader = Reader::new(rest);
                recurse_reader(&mut inner_reader, vec);
            }
            der::Tag::OID => {
                let obj = obj_to_obj(rest);
                is_subj_alt = obj.is_some() && obj.unwrap() == Object::SubjAltNames;
            }
            der::Tag::OctetString => {
                if is_subj_alt {
                    let mut name_seq = Reader::new(rest);
                    match der::read_tag_and_get_value(&mut name_seq) {
                        Ok((_, rest)) => {
                            let mut snr = Reader::new(rest);
                            while !snr.at_end() {
                                let gn = general_name(&mut snr);
                                match gn {
                                    Ok(n) => match n {
                                        GeneralName::DNSName(input) => {
                                            let name =
                                                String::from_utf8_lossy(input.as_slice_less_safe());
                                            vec.push(SubjAltName::DNSName(name));
                                        }
                                        GeneralName::IPAddress(input) => {
                                            if input.len() >= 4 {
                                                let mut a = [0; 4];
                                                let mut i = input.iter();
                                                a[0] = *i.next().unwrap();
                                                a[1] = *i.next().unwrap();
                                                a[2] = *i.next().unwrap();
                                                a[3] = *i.next().unwrap();
                                                vec.push(SubjAltName::IPAddress(a));
                                            }
                                        }
                                    },
                                    Err(_) => {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
pub enum SubjAltName<'a> {
    DNSName(Cow<'a, str>),
    IPAddress([u8; 4]),
}

pub fn get_subj_alt_names<'a>(reader: &mut Reader<'a>) -> Vec<SubjAltName<'a>> {
    let mut ret = Vec::new();
    recurse_reader(reader, &mut ret);
    ret
}
