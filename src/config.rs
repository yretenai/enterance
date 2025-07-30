use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use tracing::{debug, info};
use url::Url;

/// Application configuration structure
#[derive(Hash, PartialEq, Eq, Clone, Debug, Deserialize, Serialize)]
pub struct Config {
	/// URL for file update manifest
	pub update: String,
	/// URL for authentication endpoint
	pub login: String,
	/// URL for server list endpoint
	pub world: String,
	/// Path to game executable (relative to launcher directory)
	pub path: Option<String>,
	/// Language setting
	pub lang: Option<String>,
	/// Maximum concurrent downloads (for performance)
	pub max_concurrent_downloads: Option<usize>,
	/// Log level configuration
	pub log_level: Option<String>,
}

impl Config {
	/// Create a new default configuration
	pub fn new() -> Self {
		Config {
			update: String::new(),
			login: String::new(),
			world: String::new(),
			path: Some("Binaries/TERA.exe".to_string()),
			lang: Some("EUR".to_string()),
			max_concurrent_downloads: Some(4),
			log_level: Some("info".to_string()),
		}
	}

	/// Get the game executable path with default fallback
	pub fn game_path(&self) -> String {
		self.path.clone().unwrap_or_else(|| "Binaries/TERA.exe".to_string())
	}

	/// Get the language setting with default fallback
	pub fn language(&self) -> String {
		self.lang.clone().unwrap_or_else(|| "EUR".to_string())
	}

	/// Get the maximum concurrent downloads with default fallback
	pub fn max_concurrent_downloads(&self) -> usize {
		self.max_concurrent_downloads.unwrap_or(4)
	}

	/// Get the log level with default fallback
	pub fn log_level(&self) -> String {
		self.log_level.clone().unwrap_or_else(|| "info".to_string())
	}

	/// Validate configuration values
	pub fn validate(&self) -> Result<()> {
		// Validate URLs
		Url::parse(&self.update).with_context(|| format!("Invalid update URL in configuration: '{}'", self.update))?;
		Url::parse(&self.login).with_context(|| format!("Invalid login URL in configuration: '{}'", self.login))?;
		Url::parse(&self.world).with_context(|| format!("Invalid world URL in configuration: '{}'", self.world))?;

		// Validate path doesn't contain directory traversal
		if let Some(ref path) = self.path {
			if path.contains("..") || path.starts_with('/') || path.contains("\\..\\") {
				return Err(anyhow::anyhow!("Security violation: Game path '{}' contains directory traversal patterns", path));
			}
		}

		// Validate concurrent downloads limit
		if let Some(max_downloads) = self.max_concurrent_downloads {
			if max_downloads == 0 || max_downloads > 20 {
				return Err(anyhow::anyhow!("Invalid max_concurrent_downloads value: {} (must be 1-20)", max_downloads));
			}
		}

		// Validate log level
		if let Some(ref level) = self.log_level {
			match level.to_lowercase().as_str() {
				"error" | "warn" | "info" | "debug" | "trace" => {}
				_ => {
					return Err(anyhow::anyhow!("Invalid log level '{}' (valid: error, warn, info, debug, trace)", level));
				}
			}
		}

		Ok(())
	}
}

impl Default for Config {
	fn default() -> Self {
		Self::new()
	}
}

/// Configuration manager for loading and saving configuration
pub struct ConfigManager;

impl ConfigManager {
	/// Load configuration from file
	pub fn load() -> Result<Config> {
		let config_path = Self::get_config_path()?;
		debug!("Loading configuration from: {:?}", config_path);

		let mut file = File::open(&config_path).with_context(|| format!("Configuration file not found: {config_path:?}"))?;

		let mut contents = String::new();
		file.read_to_string(&mut contents).context("Failed to read configuration file")?;

		let config: Config = toml::from_str(&contents).context("Configuration file format is invalid (must be valid TOML)")?;

		// Validate the loaded configuration
		config.validate()?;

		info!("Configuration loaded successfully");
		Ok(config)
	}

	/// Save configuration to file
	pub fn save(config: &Config) -> Result<()> {
		// Validate before saving
		config.validate()?;

		let config_path = Self::get_config_path()?;
		debug!("Saving configuration to: {:?}", config_path);

		let mut file = File::create(&config_path).with_context(|| format!("Failed to create configuration file: {config_path:?}"))?;

		let contents = toml::to_string_pretty(config).context("Failed to serialize configuration")?;

		file.write_all(contents.as_bytes()).context("Failed to write configuration file")?;

		info!("Configuration saved successfully");
		Ok(())
	}

	/// Get the path to the configuration file
	pub fn get_config_path() -> Result<PathBuf> {
		Ok(Self::get_launcher_dir()?.join("enterance.ini"))
	}

	/// Get the launcher directory
	pub fn get_launcher_dir() -> Result<PathBuf> {
		if let Ok(path) = env::var("ENTERANCE_PATH") {
			return Ok(PathBuf::from(path));
		}

		Ok(env::current_exe()?.parent().unwrap_or(env::current_dir()?.as_path()).to_path_buf())
	}

	/// Check if configuration file exists
	pub fn config_exists() -> Result<bool> {
		Ok(Self::get_config_path()?.exists())
	}
}
