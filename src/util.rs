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

/// JSON representation of server list from the API
#[derive(Hash, PartialEq, Eq, Clone, Debug, Deserialize, Serialize)]
struct ServerListJSON {
	/// Sorting criterion for server list
	pub sort_criterion: Option<u32>,
	/// List of available servers
	pub servers: Vec<ServerInfoJSON>,
}

/// JSON representation of individual server information
#[derive(Hash, PartialEq, Eq, Clone, Debug, Deserialize, Serialize)]
struct ServerInfoJSON {
	/// Unique server identifier
	pub id: u32,
	/// Server display name
	pub name: String,
	/// Server category/type
	pub category: String,
	/// Server title/description
	pub title: String,
	/// Queue status information
	pub queue: String,
	/// Server population status
	pub population: Option<String>,
	/// Server IP address
	pub address: Option<String>,
	/// Server port number
	pub port: u32,
	/// Server availability status (1 = available, 0 = unavailable)
	pub available: u32,
	/// Message displayed when server is unavailable
	pub unavailable_message: String,
	/// Alternative hostname for connection
	pub host: Option<String>,
}

/// Authentication response from the login API
#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct LoginResponse {
	/// Whether authentication was successful
	#[serde(rename = "Return")]
	pub return_value: bool,
	/// Numeric return code (0 = success)
	#[serde(rename = "ReturnCode")]
	pub return_code: i32,
	/// Human-readable message
	#[serde(rename = "Msg")]
	pub msg: String,
	/// Number of characters on account
	#[serde(rename = "CharacterCount")]
	pub character_count: Option<String>,
	/// User permission level
	#[serde(rename = "Permission")]
	pub permission: Option<i32>,
	/// User privilege level
	#[serde(rename = "Privilege")]
	pub privilege: Option<i32>,
	/// Unique user identifier
	#[serde(rename = "UserNo")]
	pub user_no: Option<i32>,
	/// Account username
	#[serde(rename = "UserName")]
	pub user_name: Option<String>,
	/// Authentication token for subsequent requests
	#[serde(rename = "AuthKey")]
	pub auth_key: Option<String>,
}

/// Information about a single file in the update manifest
#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct FileInfo {
	/// Relative path to the file from game directory
	pub path: String,
	/// SHA256 hash of the file contents
	pub hash: String,
	/// File size in bytes
	pub size: u64,
	/// Download URL for the file
	pub url: String,
}

/// Update manifest containing all files that should be present
#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct HashFile {
	/// List of all files in the game installation
	pub files: Vec<FileInfo>,
}

/// Get the launcher installation directory
///
/// Returns the directory containing the launcher executable, which is used
/// as the base directory for all game files and configuration.
///
/// Can be overridden by setting the ENTERANCE_PATH environment variable.
pub fn get_my_dir() -> Result<PathBuf> {
	if let Ok(path) = env::var("ENTERANCE_PATH") {
		return Ok(PathBuf::from(path));
	}

	Ok(env::current_exe()?.parent().unwrap_or(env::current_dir()?.as_path()).to_path_buf())
}

/// Get the path to the file hash cache
///
/// Returns the path where file hashes are cached to avoid recalculating
/// them on every launcher run.
pub fn get_cache_file_path() -> Result<PathBuf> {
	Ok(get_my_dir()?.join("cache"))
}

/// Get the path to the authentication token file
///
/// Returns the path where authentication tokens are stored as a fallback
/// when secure storage is not available.
pub fn get_login_token_path() -> Result<PathBuf> {
	Ok(get_my_dir()?.join("auth"))
}

/// Get the path to the configuration file
///
/// Returns the path to the enterance.ini configuration file.
pub fn get_config_path() -> Result<PathBuf> {
	Ok(get_my_dir()?.join("enterance.ini"))
}

/// Get the path to the server list cache (Windows only)
///
/// Returns the path where the server list is cached locally.
#[cfg(target_os = "windows")]
pub fn get_server_path() -> Result<PathBuf> {
	Ok(get_my_dir()?.join("server"))
}

/// Load file hash cache from disk
///
/// Loads the cached file hashes to avoid recalculating them on every run.
/// Returns an empty HashMap if no cache file exists.
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

/// Write file hash cache to disk
///
/// Saves the current file hash cache to disk for use in subsequent runs.
///
/// # Arguments
/// * `hashes` - HashMap mapping file paths to their SHA256 hashes
pub fn write_cache_to_disk(hashes: HashMap<String, String>) -> Result<()> {
	let cache_path = get_cache_file_path()?;
	let file = File::create(cache_path)?;
	let mut serialize = Serializer::new(file);
	hashes.serialize(&mut serialize)?;
	Ok(())
}

/// Load authentication token from disk (Windows only)
///
/// Reads the authentication token from the local file for use with
/// the game client on Windows.
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
		let server_info = server_list::ServerInfo {
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
			host: if server.address.is_some() || server.host.is_none() { None } else { Some(utf16_to_bytes_opt(server.host.clone())) },
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

/// Read a line of input from stdin with validation
///
/// Reads user input from stdin and validates it for security:
/// - Maximum length of 255 characters
/// - No control characters except tabs
///
/// # Returns
/// The trimmed input string
pub fn read_line() -> Result<String> {
	stdout().flush()?;
	let mut line = String::new();
	stdin().read_line(&mut line)?;
	let trimmed = line.trim().to_string();

	// Basic input validation
	if trimmed.len() > 255 {
		return Err(anyhow::anyhow!("Input too long (max 255 characters)"));
	}

	// Check for control characters (except space and printable ASCII)
	if trimmed.chars().any(|c| c.is_control() && c != '\t') {
		return Err(anyhow::anyhow!("Input contains invalid control characters"));
	}

	Ok(trimmed)
}

/// Calculate SHA256 hash of a file
///
/// Reads the file in chunks and calculates its SHA256 hash for integrity verification.
///
/// # Arguments
/// * `path` - Path to the file to hash
///
/// # Returns
/// Hexadecimal string representation of the SHA256 hash
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
	Ok(format!("{result:x}"))
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
