//! Preserve JSON object insertion order only where Python's str(dict) is a form value.
//! This must not enable serde_json/preserve_order in the shared host dependency graph.
use serde::de::{Deserialize,Deserializer,MapAccess,SeqAccess,Visitor};
use serde_json::Value;
use std::fmt;
#[derive(Debug)]
pub(super) enum Ordered {Scalar(Value),Array(Vec<Ordered>),Object(Vec<(String,Ordered)>)}
impl Ordered {
 pub(super) fn get(&self,key:&str)->Option<&Ordered>{match self {Self::Object(fields)=>fields.iter().rev().find(|(name,_)|name==key).map(|(_,value)|value),_=>None}}
 pub(super) fn repr(&self,nested:bool)->String{match self {
  Self::Scalar(value)=>super::three_xui_api::python_repr(value,nested),
  Self::Array(values)=>format!("[{}]",values.iter().map(|value|value.repr(true)).collect::<Vec<_>>().join(", ")),
  Self::Object(fields)=>format!("{{{}}}",fields.iter().map(|(key,value)|format!("{}: {}",pc_host::pytext::py_repr(key),value.repr(true))).collect::<Vec<_>>().join(", ")),
 }}
}
impl<'de> Deserialize<'de> for Ordered {
 fn deserialize<D:Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
  struct OrderedVisitor;
  impl<'de> Visitor<'de> for OrderedVisitor{
   type Value=Ordered;
   fn expecting(&self,formatter:&mut fmt::Formatter<'_>)->fmt::Result{formatter.write_str("JSON value")}
   fn visit_unit<E:serde::de::Error>(self)->Result<Ordered,E>{Ok(Ordered::Scalar(Value::Null))}
   fn visit_bool<E:serde::de::Error>(self,value:bool)->Result<Ordered,E>{Ok(Ordered::Scalar(Value::Bool(value)))}
   fn visit_i64<E:serde::de::Error>(self,value:i64)->Result<Ordered,E>{Ok(Ordered::Scalar(Value::Number(value.into())))}
   fn visit_u64<E:serde::de::Error>(self,value:u64)->Result<Ordered,E>{Ok(Ordered::Scalar(Value::Number(value.into())))}
   fn visit_f64<E:serde::de::Error>(self,value:f64)->Result<Ordered,E>{serde_json::Number::from_f64(value).map(|value|Ordered::Scalar(Value::Number(value))).ok_or_else(||E::custom("non-finite JSON number"))}
   fn visit_str<E:serde::de::Error>(self,value:&str)->Result<Ordered,E>{Ok(Ordered::Scalar(Value::String(value.into())))}
   fn visit_string<E:serde::de::Error>(self,value:String)->Result<Ordered,E>{Ok(Ordered::Scalar(Value::String(value)))}
   fn visit_seq<A:SeqAccess<'de>>(self,mut sequence:A)->Result<Ordered,A::Error>{let mut values=Vec::new();while let Some(value)=sequence.next_element()?{values.push(value);}Ok(Ordered::Array(values))}
   fn visit_map<A:MapAccess<'de>>(self,mut map:A)->Result<Ordered,A::Error>{let mut fields=Vec::new();while let Some((key,value))=map.next_entry()?{fields.push((key,value));}Ok(Ordered::Object(fields))}
  }
  deserializer.deserialize_any(OrderedVisitor)
 }
}
