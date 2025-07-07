#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerList {
	#[prost(message, repeated, tag = "1")]
	pub servers: ::prost::alloc::vec::Vec<ServerInfo>,
	#[prost(fixed32, tag = "2")]
	pub last_server_id: u32,
	#[prost(fixed32, tag = "3")]
	pub sort_criterion: u32,
}
#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct ServerInfo {
	#[prost(fixed32, tag = "1")]
	pub id: u32,
	#[prost(bytes = "vec", tag = "2")]
	pub name: ::prost::alloc::vec::Vec<u8>,
	#[prost(bytes = "vec", tag = "3")]
	pub category: ::prost::alloc::vec::Vec<u8>,
	#[prost(bytes = "vec", tag = "4")]
	pub title: ::prost::alloc::vec::Vec<u8>,
	#[prost(bytes = "vec", tag = "5")]
	pub queue: ::prost::alloc::vec::Vec<u8>,
	#[prost(bytes = "vec", tag = "6")]
	pub population: ::prost::alloc::vec::Vec<u8>,
	#[prost(fixed32, tag = "7")]
	pub address: u32,
	#[prost(fixed32, tag = "8")]
	pub port: u32,
	#[prost(fixed32, tag = "9")]
	pub available: u32,
	#[prost(bytes = "vec", tag = "10")]
	pub unavailable_message: ::prost::alloc::vec::Vec<u8>,
	#[prost(bytes = "vec", tag = "11")]
	pub host: ::prost::alloc::vec::Vec<u8>,
}
