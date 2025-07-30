#[cfg(target_os = "windows")]
mod game;
#[cfg(target_os = "windows")]
pub mod serverlist {
	include!(concat!(env!("OUT_DIR"), "/tera.rs"));
}

mod config;
mod errors;
mod http;
mod util;

use crate::config::{Config, ConfigManager};
use crate::errors::*;
use crate::http::{HttpClient, HttpConfig};
use crate::util::*;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures::stream::{self, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use serde::Serialize;
use serde_json::Serializer;
use std::fs::{File, exists};
use std::io::{Read, Write};
use std::process::exit;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// Initialize logging based on CLI arguments and configuration
fn init_logging(cli: &Cli) -> Result<()> {
	let log_level = if cli.verbose {
		"debug".to_string()
	} else if cli.quiet {
		"error".to_string()
	} else {
		// Try to load from config, fallback to info
		match ConfigManager::load() {
			Ok(config) => config.log_level(),
			Err(_) => "info".to_string(),
		}
	};

	let filter = EnvFilter::try_new(format!("enterance={log_level}"))
		.or_else(|_| EnvFilter::try_new("info"))
		.context("Failed to create log filter")?;

	let subscriber = FmtSubscriber::builder().with_env_filter(filter).with_target(false).finish();

	tracing::subscriber::set_global_default(subscriber).context("Failed to set default subscriber")?;

	debug!("Logging initialized with level: {}", log_level);
	Ok(())
}

/// Command-line interface structure for the enterance launcher
#[derive(Parser)]
#[command(name = "enterance")]
#[command(about = "A minimal TERA Launcher replacement written in Rust")]
#[command(version)]
struct Cli {
	/// Optional subcommand to execute
	#[command(subcommand)]
	command: Option<Commands>,

	/// Enable verbose output (debug logging)
	#[arg(short, long)]
	verbose: bool,

	/// Suppress all output except errors
	#[arg(short, long)]
	quiet: bool,

	/// Path to config file (currently unused)
	#[arg(long, value_name = "FILE")]
	config_path: Option<String>,

	/// Show what would be done without making changes (currently unused)
	#[arg(long)]
	dry_run: bool,

	/// Skip file update process and launch game directly
	#[arg(long)]
	no_update: bool,
}

/// Available subcommands for the launcher
#[derive(Subcommand)]
enum Commands {
	/// Authenticate with credentials and save auth token
	Login {
		/// Username for authentication (will prompt if not provided)
		#[arg(short, long)]
		username: Option<String>,
	},
	/// Update game files from remote manifest
	Update {
		/// Skip hash verification (currently unused)
		#[arg(long)]
		no_verify: bool,
	},
	/// Configure the launcher settings
	Config {
		/// Show current configuration values
		#[arg(long)]
		show: bool,
		/// Initialize interactive configuration wizard
		#[arg(long)]
		init: bool,
	},
	/// Verify game file integrity against remote manifest
	Verify,
	/// Clean cache and temporary files  
	Clean {
		/// Remove authentication tokens from secure storage and files
		#[arg(long)]
		auth: bool,
		/// Remove file hash cache
		#[arg(long)]
		cache: bool,
	},
}

/// Main entry point for the enterance launcher
///
/// Initializes logging, parses command-line arguments, and executes the appropriate subcommand
/// or runs the full launcher workflow.
#[tokio::main]
async fn main() -> Result<()> {
	let cli = Cli::parse();

	// Initialize logging
	init_logging(&cli)?;

	println!("enterance launcher starting...");

	// Handle subcommands
	match cli.command {
		Some(Commands::Login {
			username,
		}) => {
			return handle_login(username).await;
		}
		Some(Commands::Update {
			no_verify,
		}) => {
			return handle_update(no_verify, cli.verbose).await;
		}
		Some(Commands::Config {
			show,
			init,
		}) => {
			return handle_config(show, init).await;
		}
		Some(Commands::Verify) => {
			return handle_verify(cli.verbose).await;
		}
		Some(Commands::Clean {
			auth,
			cache,
		}) => {
			return handle_clean(auth, cache).await;
		}
		None => {
			// Default behavior - run full launcher
			return run_launcher(cli.verbose, cli.no_update).await;
		}
	}
}

/// Handle the login subcommand
///
/// Prompts for credentials (if not provided), authenticates with the server,
/// and stores the authentication token to file.
///
/// # Arguments
/// * `username` - Optional username; will prompt if not provided
async fn handle_login(username: Option<String>) -> Result<()> {
	let username = if let Some(u) = username {
		u
	} else {
		print!("Login: ");
		read_line()?
	};

	print!("Password: ");
	let password = read_line()?;
	println!("Logging in...");

	login(username, password).await?;
	println!("Authentication successful");
	Ok(())
}

/// Handle the update subcommand
///
/// Updates game files by comparing local files against the remote manifest
/// and downloading any files that are missing or have changed hashes.
///
/// # Arguments
/// * `_no_verify` - Skip hash verification (currently unused)
/// * `_verbose` - Enable verbose output (currently unused, handled by logging)
async fn handle_update(_no_verify: bool, _verbose: bool) -> Result<()> {
	if !ConfigManager::config_exists()? {
		return Err(EnteranceError::ConfigNotFound.into());
	}

	let config = ConfigManager::load()?;
	run_update_process(&config).await.with_context(|| "Failed during file updates")
}

/// Handle the config subcommand
///
/// Either shows the current configuration or runs the interactive configuration wizard.
///
/// # Arguments
/// * `show` - Display current configuration values
/// * `init` - Run interactive configuration wizard
async fn handle_config(show: bool, init: bool) -> Result<()> {
	if init {
		return create_config_interactive().await.with_context(|| "Failed to create configuration");
	}

	if show {
		let config = ConfigManager::load().with_context(|| "Failed to load configuration")?;
		println!("Current configuration:");
		println!("   Update URL: {}", config.update);
		println!("   Login URL: {}", config.login);
		println!("   World URL: {}", config.world);
		println!("   Game Path: {}", config.game_path());
		println!("   Language: {}", config.language());
		println!("   Max Concurrent Downloads: {}", config.max_concurrent_downloads());
		println!("   Log Level: {}", config.log_level());
	}

	Ok(())
}

/// Handle the verify subcommand
///
/// Verifies the integrity of all game files against the remote manifest
/// without downloading any files.
///
/// # Arguments
/// * `_verbose` - Enable verbose output (currently unused, handled by logging)
async fn handle_verify(_verbose: bool) -> Result<()> {
	if !ConfigManager::config_exists()? {
		return Err(EnteranceError::ConfigNotFound.into());
	}

	let config = ConfigManager::load()?;
	info!("Starting file verification");
	run_verification_only(&config).await.with_context(|| "Failed during file verification")
}

/// Handle the clean subcommand
///
/// Removes authentication tokens and/or file cache based on the provided flags.
///
/// # Arguments
/// * `auth` - Remove authentication token file
/// * `cache` - Remove file hash cache
async fn handle_clean(auth: bool, cache: bool) -> Result<()> {
	if auth {
		// Clean auth token file
		let token_path = get_login_token_path()?;
		if exists(&token_path)? {
			std::fs::remove_file(&token_path).with_context(|| "Failed to remove authentication file")?;
			info!("Removed authentication file: {:?}", token_path);
			println!("Removed authentication file");
		}
	}

	if cache {
		let cache_path = get_cache_file_path()?;
		if exists(&cache_path)? {
			std::fs::remove_file(&cache_path).with_context(|| "Failed to remove cache file")?;
			info!("Removed file cache: {:?}", cache_path);
			println!("Removed file cache");
		}
	}

	if !auth && !cache {
		println!("   No cleanup options specified.");
		println!("   Use --auth to remove authentication tokens");
		println!("   Use --cache to remove file cache");
		println!("   Example: enterance clean --auth --cache");
	}

	Ok(())
}

/// Run the full launcher workflow
///
/// This is the default behavior when no subcommand is specified. It handles
/// authentication, file updates, and game launching (on Windows).
///
/// # Arguments
/// * `_verbose` - Enable verbose output (currently unused, handled by logging)
/// * `no_update` - Skip file update process and launch game directly
async fn run_launcher(_verbose: bool, no_update: bool) -> Result<()> {
	// Auto-create config if missing (like original)
	if !exists(get_config_path()?)? {
		eprintln!("Config file does not exist! saving a default one...");
		let config_path = get_config_path()?;
		let mut file = File::create(config_path)?;
		let contents = toml::to_string(&Config::new())?;
		file.write_all(contents.into_bytes().as_ref())?;
		return Ok(());
	}

	if !exists(get_login_token_path()?)? {
		print!("Login: ");
		let username = read_line()?;
		print!("Password: ");
		let password = read_line()?;
		println!("Logging in...");
		login(username, password).await?;
	}

	if !no_update {
		let config = get_config()?;
		run_update_process(&config).await?;
	}

	#[cfg(target_os = "windows")]
	{
		let config = get_config()?;
		let game_path = get_my_dir()?.join(config.game_path());
		info!("Launching game: {:?}", game_path);
		game::launch(game_path).await?;
	}

	Ok(())
}

/// Get configuration from file (simple version like original)
fn get_config() -> Result<Config> {
	let config_path = get_config_path()?;
	let mut file = File::open(config_path).expect("enterance.ini not found!");
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;
	Ok(toml::from_str(&contents)?)
}

/// Simple authentication function that saves token to file
async fn login(username: String, password: String) -> Result<()> {
	let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().context("Failed to create HTTP client")?;
	let config = get_config()?;

	let req = client.post(&config.login);
	let res = req.form(&vec![("login", username), ("password", password)]).send().await?;

	let json: LoginResponse = res.json().await?;
	if !json.return_value {
		eprintln!("Invalid login! {} {}", json.return_code, json.msg);
		exit(1);
	}

	let token_path = get_login_token_path()?;
	println!("Saving {token_path:?}");

	let file = File::create(token_path)?;
	let mut serialize = Serializer::new(file);
	json.serialize(&mut serialize)?;

	Ok(())
}

/// Execute the file update process with concurrent downloads
///
/// This function:
/// 1. Loads the local file cache
/// 2. Fetches the remote file manifest
/// 3. Compares local files against the manifest
/// 4. Downloads missing or changed files concurrently
/// 5. Updates the local cache
///
/// # Arguments
/// * `config` - Application configuration containing URLs and settings
async fn run_update_process(config: &Config) -> Result<()> {
	info!("Starting update process");
	let mut local_cache = load_cache_from_disk()?;
	if local_cache.is_empty() {
		info!("No local cache found. First run will take some time.");
		println!("No local cache found. First run will take some time.");
	}

	// Create HTTP client with concurrent download configuration
	let http_config = HttpConfig {
		max_concurrent_downloads: config.max_concurrent_downloads(),
		..Default::default()
	};
	let http_client = HttpClient::new(http_config)?;

	// Fetch update manifest
	let req = http_client.client().get(&config.update);
	let res = req.send().await.context("Failed to fetch update manifest")?;
	let hashes = res.json::<HashFile>().await.context("Failed to parse update manifest")?;

	let launcher_dir = ConfigManager::get_launcher_dir()?;

	// Create progress bars
	let multi_progress = MultiProgress::new();
	let main_pb = multi_progress.add(ProgressBar::new(hashes.files.len() as u64));
	main_pb.set_style(
		ProgressStyle::default_bar()
			.template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
			.unwrap()
			.progress_chars("#>-"),
	);
	main_pb.set_message("Analyzing files");

	// First pass: determine which files need downloading
	let mut files_to_download = Vec::new();

	for info in &hashes.files {
		// Validate file path to prevent directory traversal
		if info.path.contains("..") || info.path.starts_with('/') || info.path.contains("\\..\\") {
			warn!("Skipping unsafe file path: {}", info.path);
			main_pb.println(format!("Warning: Skipping unsafe file path: {}", info.path));
			main_pb.inc(1);
			continue;
		}

		main_pb.set_message(format!("Checking {}", info.path));

		let target_file = launcher_dir.join(&info.path);
		let needs_download = if let Some(existing) = local_cache.get(&info.path) {
			!existing.eq_ignore_ascii_case(&info.hash)
		} else if exists(&target_file)? {
			let local_hash = calculate_file_hash(&target_file)?;
			let hash_matches = local_hash.eq_ignore_ascii_case(&info.hash);
			if hash_matches {
				local_cache.insert(info.path.clone(), local_hash);
			}
			!hash_matches
		} else {
			true
		};

		if needs_download {
			files_to_download.push(info.clone());
		}

		main_pb.inc(1);
	}

	main_pb.finish_with_message(format!("Analysis complete - {} files need updating", files_to_download.len()));

	if files_to_download.is_empty() {
		info!("All files are up to date");
		println!("All files are up to date");
		return Ok(());
	}

	info!("Starting concurrent downloads for {} files", files_to_download.len());

	// Second pass: download files concurrently
	let download_pb = multi_progress.add(ProgressBar::new(files_to_download.len() as u64));
	download_pb.set_style(
		ProgressStyle::default_bar()
			.template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} downloads ({eta})")
			.unwrap()
			.progress_chars("#>-"),
	);
	download_pb.set_message("Downloading files");

	let http_client = Arc::new(http_client);
	let multi_progress = Arc::new(multi_progress);
	let download_pb = Arc::new(download_pb);
	let launcher_dir = Arc::new(launcher_dir);

	// Process downloads with concurrency limit
	let download_results: Vec<Result<(String, String)>> = stream::iter(files_to_download)
		.map(|file_info| {
			let http_client = Arc::clone(&http_client);
			let multi_progress = Arc::clone(&multi_progress);
			let download_pb = Arc::clone(&download_pb);
			let launcher_dir = Arc::clone(&launcher_dir);

			async move {
				let result =
					download_file_concurrent(Arc::clone(&http_client), Arc::clone(&multi_progress), &file_info, Arc::clone(&launcher_dir))
						.await;

				download_pb.inc(1);
				result
			}
		})
		.buffer_unordered(http_client.max_concurrent_downloads())
		.collect()
		.await;

	// Process results and update cache
	let mut successful_downloads = 0;
	let mut failed_downloads = 0;

	for result in download_results {
		match result {
			Ok((path, hash)) => {
				local_cache.insert(path, hash);
				successful_downloads += 1;
			}
			Err(e) => {
				error!("Download failed: {}", e);
				failed_downloads += 1;
			}
		}
	}

	download_pb.finish_with_message(format!("Downloads complete - {successful_downloads} successful, {failed_downloads} failed"));

	if failed_downloads > 0 {
		warn!("{} downloads failed", failed_downloads);
		return Err(anyhow::anyhow!("{} downloads failed", failed_downloads));
	}

	write_cache_to_disk(local_cache)?;
	info!("Update process completed successfully");
	Ok(())
}

/// Download a single file with progress reporting and retry logic
///
/// This function handles the concurrent download of a single file with:
/// - Semaphore-controlled concurrency
/// - Individual progress bars
/// - Retry logic with exponential backoff
/// - Directory creation as needed
///
/// # Arguments
/// * `http_client` - Shared HTTP client with concurrency control
/// * `multi_progress` - Progress bar manager for UI updates
/// * `file_info` - Information about the file to download (path, hash, size, URL)
/// * `launcher_dir` - Base directory for the game installation
///
/// # Returns
/// A tuple containing the file path and expected hash for cache updates
async fn download_file_concurrent(
	http_client: Arc<HttpClient>,
	multi_progress: Arc<MultiProgress>,
	file_info: &FileInfo,
	launcher_dir: Arc<std::path::PathBuf>,
) -> Result<(String, String)> {
	let _permit = http_client.acquire_permit().await?;

	let target_file = launcher_dir.join(&file_info.path);

	// Create parent directories if needed
	if let Some(parent_path) = target_file.parent() {
		if !exists(parent_path)? {
			std::fs::create_dir_all(parent_path).with_context(|| format!("Failed to create directory: {parent_path:?}"))?;
		}
	}

	// Create individual progress bar for this download
	let file_pb = multi_progress.add(ProgressBar::new(file_info.size));
	file_pb.set_style(
		ProgressStyle::default_bar()
			.template("  {spinner:.green} [{bar:30.cyan/blue}] {bytes}/{total_bytes} {msg}")
			.unwrap()
			.progress_chars("#>-"),
	);
	file_pb.set_message(file_info.path.to_string());

	debug!("Downloading file: {} -> {:?}", file_info.url, target_file);

	// Download with retries
	let response =
		http_client.download_with_retries(&file_info.url).await.with_context(|| format!("Failed to download {}", file_info.path))?;

	// Stream download with progress
	let mut file = File::create(&target_file).with_context(|| format!("Failed to create file: {target_file:?}"))?;

	let mut stream = response.bytes_stream();
	use futures_util::StreamExt;

	while let Some(chunk_result) = stream.next().await {
		let chunk = chunk_result.with_context(|| format!("Failed to read chunk for {}", file_info.path))?;
		file.write_all(&chunk).with_context(|| format!("Failed to write chunk for {}", file_info.path))?;
		file_pb.inc(chunk.len() as u64);
	}

	file_pb.finish_with_message("Done");
	debug!("Successfully downloaded: {}", file_info.path);

	Ok((file_info.path.clone(), file_info.hash.clone()))
}

/// Verify game file integrity without downloading
///
/// Compares local file hashes against the remote manifest to identify
/// missing or corrupted files without actually downloading them.
///
/// # Arguments
/// * `config` - Application configuration containing the update manifest URL
async fn run_verification_only(config: &Config) -> Result<()> {
	info!("Starting file verification");
	let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().context("Failed to create HTTP client")?;
	let req = client.get(&config.update);
	let res = req.send().await.context("Failed to fetch update manifest")?;
	let hashes = res.json::<HashFile>().await.context("Failed to parse update manifest")?;

	let launcher_dir = ConfigManager::get_launcher_dir()?;
	let main_pb = ProgressBar::new(hashes.files.len() as u64);
	main_pb.set_style(
		ProgressStyle::default_bar()
			.template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
			.unwrap()
			.progress_chars("#>-"),
	);
	main_pb.set_message("Verifying files");

	let mut issues = Vec::new();

	for info in &hashes.files {
		main_pb.set_message(format!("Verifying {}", info.path));

		// Skip unsafe paths
		if info.path.contains("..") || info.path.starts_with('/') || info.path.contains("\\..\\") {
			warn!("Skipping unsafe file path during verification: {}", info.path);
			main_pb.inc(1);
			continue;
		}

		let target_file = launcher_dir.join(&info.path);
		if !exists(&target_file)? {
			warn!("Missing file: {}", info.path);
			issues.push(format!("Missing: {}", info.path));
		} else {
			let local_hash = calculate_file_hash(&target_file)?;
			if !local_hash.eq_ignore_ascii_case(&info.hash) {
				warn!("Hash mismatch: {}", info.path);
				issues.push(format!("Hash mismatch: {}", info.path));
			} else {
				debug!("File verified: {}", info.path);
			}
		}

		main_pb.inc(1);
	}

	main_pb.finish_with_message("Verification complete");

	if issues.is_empty() {
		info!("All files verified successfully");
		println!("All files verified successfully");
	} else {
		error!("Found {} issues during verification", issues.len());
		println!("Found {} issues:", issues.len());
		for issue in issues {
			println!("  {issue}");
		}
	}

	Ok(())
}

/// Run the interactive configuration wizard
///
/// Prompts the user for all necessary configuration values and saves
/// them to the configuration file with validation.
async fn create_config_interactive() -> Result<()> {
	use dialoguer::{Confirm, Input};

	println!("enterance Configuration Wizard");
	println!("This will create a new configuration file.");

	if ConfigManager::config_exists()? {
		let overwrite = Confirm::new().with_prompt("Configuration file already exists. Overwrite?").default(false).interact()?;

		if !overwrite {
			println!("Configuration wizard cancelled.");
			return Ok(());
		}
	}

	let update_url: String = Input::new().with_prompt("Update manifest URL").with_initial_text("https://").interact_text()?;

	let login_url: String = Input::new().with_prompt("Login API URL").with_initial_text("http://").interact_text()?;

	let world_url: String = Input::new().with_prompt("World/Server list URL").with_initial_text("https://").interact_text()?;

	let game_path: String = Input::new().with_prompt("Game executable path").default("Binaries/TERA.exe".to_string()).interact_text()?;

	let language: String = Input::new().with_prompt("Language code").default("EUR".to_string()).interact_text()?;

	let max_concurrent: usize = Input::new()
		.with_prompt("Maximum concurrent downloads (1-20)")
		.default(4)
		.validate_with(|input: &usize| -> Result<(), &str> {
			if *input >= 1 && *input <= 20 { Ok(()) } else { Err("Must be between 1 and 20") }
		})
		.interact_text()?;

	let log_level: String = Input::new()
		.with_prompt("Log level (error, warn, info, debug, trace)")
		.default("info".to_string())
		.validate_with(|input: &String| -> Result<(), &str> {
			match input.to_lowercase().as_str() {
				"error" | "warn" | "info" | "debug" | "trace" => Ok(()),
				_ => Err("Must be one of: error, warn, info, debug, trace"),
			}
		})
		.interact_text()?;

	let config = Config {
		update: update_url,
		login: login_url,
		world: world_url,
		path: Some(game_path),
		lang: Some(language),
		max_concurrent_downloads: Some(max_concurrent),
		log_level: Some(log_level.to_lowercase()),
	};

	ConfigManager::save(&config)?;
	let config_path = ConfigManager::get_config_path()?;

	info!("Configuration saved to: {:?}", config_path);
	println!("Configuration saved to: {config_path:?}");
	Ok(())
}
