#[cfg(target_os = "windows")]
use crate::tera::ServerList;
#[cfg(target_os = "windows")]
use crate::tera::server_list::ServerInfo;

#[cfg(target_os = "windows")]
use prost::Message;
#[cfg(target_os = "windows")]
use serde_json::Value;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Serializer;
use sha2::{Digest, Sha256};

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write, stdin, stdout};
use std::path::{Path, PathBuf};

#[derive(Deserialize, Serialize)]
pub struct Config {
	pub update: String,
	pub login: String,
	pub world: String,
}

impl Config {
	pub(crate) fn new() -> Self {
		Config {
			update: "".to_string(),
			login: "".to_string(),
			world: "".to_string(),
		}
	}
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
	pub character_count: String,
	#[serde(rename = "Permission")]
	pub permission: i32,
	#[serde(rename = "Privilege")]
	pub privilege: i32,
	#[serde(rename = "UserNo")]
	pub user_no: i32,
	#[serde(rename = "UserName")]
	pub user_name: String,
	#[serde(rename = "AuthKey")]
	pub auth_key: String,
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
fn parse_server_list_json(json: &Value) -> Result<ServerList> {
	let mut server_list = ServerList {
		servers: vec![],
		last_server_id: 0,
		sort_criterion: 2,
	};

	let credentials = load_auth_from_disk()?.auth_key;
	println!("Raw credentials string: {}", credentials);

	let parts: Vec<&str> = credentials.split('|').collect();

	let player_last_server = parts.first().unwrap_or(&"0");
	let player_last_server_id =
		if parts.len() > 1 && !parts[1].is_empty() { parts[1].split(',').next().unwrap_or("0").parse::<u32>().unwrap_or(0) } else { 2800 };

	// Parse character counts for each server
	let character_counts: HashMap<u32, u32> = if parts.len() > 1 {
		parts[1]
			.split(',')
			.collect::<Vec<&str>>()
			.chunks(2)
			.filter_map(|chunk| if chunk.len() == 2 { Some((chunk[0].parse::<u32>().ok()?, chunk[1].parse::<u32>().ok()?)) } else { None })
			.collect()
	} else {
		HashMap::new()
	};

	println!(
		"Parsed values - Last server: {}, Last server ID: {}, Character counts: {:?}",
		player_last_server, player_last_server_id, character_counts
	);

	let servers = json["servers"].as_array().unwrap_or(&vec![]).clone();
	for server in servers {
		let server_id = server["id"].as_u64().expect("need an id") as u32;
		let character_count = character_counts.get(&server_id).cloned().unwrap_or(0);

		let json_available = server["available"].as_u64().unwrap_or(0);

		println!("Processing server: id={}, name={}, json_available={}", server_id, server["name"], json_available);

		let display_count = format!("({})", character_count);
		let name = format!("{}{}", server["name"].as_str().expect("Missing or invalid 'name' field"), display_count);
		let title = format!("{}{}", server["title"].as_str().expect("Missing or invalid 'title' field"), display_count);

		println!("Formatted server name: {}", name);

		// Modify population field based on 'available' in JSON
		let population = if json_available == 0 {
			"<b><font color=\"#FF0000\">Offline</font></b>".to_string()
		} else {
			server["population"].as_str().expect("Missing or invalid 'population' field").to_string()
		};

		// Handle address and host fields
		let address_str = server["address"].as_str();
		let host_str = server["host"].as_str();

		let (address, host) = match (address_str, host_str) {
			(Some(addr), Some(_)) => {
				// If both are present, use address and ignore host
				(ipv4_to_u32(addr), Vec::new())
			}
			(Some(addr), None) => (ipv4_to_u32(addr), Vec::new()),
			(None, Some(h)) => (0, utf16_to_bytes(h)),
			(None, None) => panic!("Either 'address' or 'host' must be set"),
		};

		let server_info = ServerInfo {
			id: server_id,
			name: utf16_to_bytes(&name),
			category: utf16_to_bytes(server["category"].as_str().expect("Missing or invalid 'category' field")),
			title: utf16_to_bytes(&title),
			queue: utf16_to_bytes(server["queue"].as_str().expect("Missing or invalid 'queue' field")),
			population: utf16_to_bytes(&population),
			address,
			port: server["port"].as_u64().expect("Missing or invalid 'port' field") as u32,
			available: 1,
			unavailable_message: utf16_to_bytes(server["unavailable_message"].as_str().unwrap_or("")),
			host,
		};
		server_list.servers.push(server_info);
	}

	server_list.last_server_id = player_last_server_id;
	server_list.sort_criterion = json["sort_criterion"].as_u64().unwrap_or(3) as u32;

	Ok(server_list)
}

#[cfg(target_os = "windows")]
pub fn load_server_from_disk() -> Result<Vec<u8>> {
	let cache_path = get_server_path()?;
	let mut file = File::open(cache_path)?;
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;
	let json: Value = serde_json::from_str(&contents)?;
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
fn ipv4_to_u32(ip: &str) -> u32 {
	ip.parse::<std::net::Ipv4Addr>().map(|addr| u32::from_be_bytes(addr.octets())).unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn utf16_to_bytes(s: &str) -> Vec<u8> {
	s.encode_utf16().flat_map(|c| c.to_le_bytes().to_vec()).collect()
}
