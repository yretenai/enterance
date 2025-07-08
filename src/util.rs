#[cfg(target_os = "windows")]
use crate::serverlist::*;

#[cfg(target_os = "windows")]
use prost::Message;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Serializer;
use sha2::{Digest, Sha256};

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write, stdin, stdout};
use std::path::{Path, PathBuf};

#[derive(Hash, PartialEq, Eq, Clone, Debug, Deserialize, Serialize)]
pub struct Config {
	pub update: String,
	pub login: String,
	pub world: String,
	pub path: Option<String>,
	pub lang: Option<String>,
}

impl Config {
	pub(crate) fn new() -> Self {
		Config {
			update: "".to_string(),
			login: "".to_string(),
			world: "".to_string(),
			path: Some("Binaries/TERA.exe".to_string()),
			lang: Some("EUR".to_string()),
		}
	}
}

#[derive(Hash, PartialEq, Eq, Clone, Debug, Deserialize, Serialize)]
struct ServerListJSON {
	pub sort_criterion: Option<u32>,
	pub servers: Vec<ServerInfoJSON>,
}

#[derive(Hash, PartialEq, Eq, Clone, Debug, Deserialize, Serialize)]
struct ServerInfoJSON {
	pub id: u32,
	pub name: String,
	pub category: String,
	pub title: String,
	pub queue: String,
	pub population: Option<String>,
	pub address: Option<String>,
	pub port: u32,
	pub available: u32,
	pub unavailable_message: String,
	pub host: Option<String>,
}

#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct LoginResponse {
	#[serde(rename = "Return")]
	pub return_value: bool,
	#[serde(rename = "ReturnCode")]
	pub return_code: i32,
	#[serde(rename = "Msg")]
	pub msg: String,
	#[serde(rename = "CharacterCount")]
	pub character_count: Option<String>,
	#[serde(rename = "Permission")]
	pub permission: Option<i32>,
	#[serde(rename = "Privilege")]
	pub privilege: Option<i32>,
	#[serde(rename = "UserNo")]
	pub user_no: Option<i32>,
	#[serde(rename = "UserName")]
	pub user_name: Option<String>,
	#[serde(rename = "AuthKey")]
	pub auth_key: Option<String>,
}

#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct FileInfo {
	pub path: String,
	pub hash: String,
	pub size: u64,
	pub url: String,
}

#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct HashFile {
	pub files: Vec<FileInfo>,
}

pub fn get_config() -> Result<Config> {
	let config_path = get_config_path()?;
	let mut file = File::open(config_path).expect("enterance.ini not found!");
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;
	Ok(toml::from_str(&contents)?)
}

pub fn get_my_dir() -> Result<PathBuf> {
	if let Ok(path) = env::var("ENTERANCE_PATH") {
		return Ok(PathBuf::from(path));
	}

	Ok(env::current_exe()?.parent().unwrap_or(env::current_dir()?.as_path()).to_path_buf())
}

pub fn get_cache_file_path() -> Result<PathBuf> {
	Ok(get_my_dir()?.join("cache"))
}

pub fn get_login_token_path() -> Result<PathBuf> {
	Ok(get_my_dir()?.join("auth"))
}

pub fn get_config_path() -> Result<PathBuf> {
	Ok(get_my_dir()?.join("enterance.ini"))
}

#[cfg(target_os = "windows")]
pub fn get_server_path() -> Result<PathBuf> {
	Ok(get_my_dir()?.join("server"))
}

pub fn load_cache_from_disk() -> Result<HashMap<String, String>> {
	let cache_path = get_cache_file_path()?;
	if !cache_path.exists() {
		return Ok(HashMap::new());
	}

	let mut file = File::open(cache_path)?;
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;
	let cache: HashMap<String, String> = serde_json::from_str(&contents)?;
	Ok(cache)
}

pub fn write_cache_to_disk(hashes: HashMap<String, String>) -> Result<()> {
	let cache_path = get_cache_file_path()?;
	let file = File::create(cache_path)?;
	let mut serialize = Serializer::new(file);
	hashes.serialize(&mut serialize)?;
	Ok(())
}

#[cfg(target_os = "windows")]
pub fn load_auth_from_disk() -> Result<LoginResponse> {
	let cache_path = get_login_token_path()?;
	let mut file = File::open(cache_path)?;
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;
	Ok(serde_json::from_str(&contents)?)
}

#[cfg(target_os = "windows")]
fn parse_server_list_json(server_json: &ServerListJSON) -> Result<ServerList> {
	let mut server_list = ServerList {
		servers: vec![],
		last_server_id: 2800,
		sort_criterion: server_json.sort_criterion.unwrap_or(3),
	};

	for server in &server_json.servers {
		let name = format!("{}(0)", server.name);
		let title = format!("{}(0)", server.title);
		let server_info = ServerInfo {
			id: server.id,
			name: utf16_to_bytes(&name),
			category: utf16_to_bytes(&server.category),
			title: utf16_to_bytes(&title),
			queue: utf16_to_bytes(&server.queue),
			population: utf16_to_bytes(&server.population.clone().unwrap_or("<b><font color=\"#FF0000\">Offline</font></b>".parse()?)),
			address: ipv4_to_u32(server.address.clone()),
			port: server.port,
			available: server.available,
			unavailable_message: utf16_to_bytes(&server.unavailable_message),
			host: if server.address.is_some() { vec![] } else { utf16_to_bytes_opt(server.host.clone()) },
		};
		server_list.servers.push(server_info);
	}

	Ok(server_list)
}

#[cfg(target_os = "windows")]
pub fn load_server_from_disk() -> Result<Vec<u8>> {
	let cache_path = get_server_path()?;
	let mut file = File::open(cache_path)?;
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;
	let json: ServerListJSON = serde_json::from_str(&contents)?;
	let server_list = parse_server_list_json(&json)?;
	let mut buf = Vec::new();
	server_list.encode(&mut buf)?;
	Ok(buf)
}

pub fn read_line() -> Result<String> {
	stdout().flush()?;
	let mut line = String::new();
	stdin().read_line(&mut line)?;
	Ok(line.trim().to_string())
}

pub(crate) fn calculate_file_hash<P: AsRef<Path>>(path: P) -> Result<String> {
	let mut file = File::open(path)?;
	let mut hasher = Sha256::new();
	let mut buffer = [0; 1024];

	loop {
		let bytes_read = file.read(&mut buffer)?;
		if bytes_read == 0 {
			break;
		}
		hasher.update(&buffer[..bytes_read]);
	}

	let result = hasher.finalize();
	Ok(format!("{:x}", result))
}

#[cfg(target_os = "windows")]
fn ipv4_to_u32(ip: Option<String>) -> u32 {
	if ip.is_none() {
		return 0;
	}

	ip.unwrap().parse::<std::net::Ipv4Addr>().map(|addr| u32::from_be_bytes(addr.octets())).unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn utf16_to_bytes(s: &String) -> Vec<u8> {
	if s.is_empty() {
		return vec![];
	}

	s.as_str().encode_utf16().flat_map(|c| c.to_le_bytes().to_vec()).collect()
}

#[cfg(target_os = "windows")]
fn utf16_to_bytes_opt(s: Option<String>) -> Vec<u8> {
	if s.is_none() {
		return vec![];
	}

	s.unwrap().as_str().encode_utf16().flat_map(|c| c.to_le_bytes().to_vec()).collect()
}
