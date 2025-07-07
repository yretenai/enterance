#[cfg(target_os = "windows")]
mod game;
#[cfg(target_os = "windows")]
mod serverlist;

mod util;

use crate::util::*;

use anyhow::Result;

use std::env::args;
use std::fs::{File, exists};
use std::io::Write;

#[tokio::main]
async fn main() -> Result<()> {
	if !exists(get_config_path()?)? {
		eprintln!("Config file does not exist! saving a default one...");
		let config_path = get_config_path()?;
		let mut file = File::create(config_path)?;
		let contents = toml::to_string(&Config::new())?;
		file.write_all(contents.into_bytes().as_ref())?;
		return Ok(());
	}

	let no_update = args().any(|arg| arg == "--no-update");

	if !exists(get_login_token_path()?)? {
		print!("Login: ");
		let username = read_line()?;
		print!("Password: ");
		let password = read_line()?;
		println!("Logging in...");
		login(username, password).await?;
	}

	if !no_update {
		println!("Now updating...");
		let mut local_cache = load_cache_from_disk()?;
		if local_cache.is_empty() {
			println!("No local cache found. First run will take some time.");
		}

		let client = reqwest::Client::new();

		let req = client.get(get_config()?.update);
		let res = req.send().await?;

		let hashes = res.json::<HashFile>().await?;

		let my_path = get_my_dir()?;
		let mut index = 1;
		for info in &hashes.files {
			print!("checking {:?}/{:?} {:?}", index, hashes.files.len(), &info.path);
			#[cfg(not(target_os = "windows"))]
			print!("{}\r", termion::clear::AfterCursor);
			#[cfg(target_os = "windows")]
			println!();
			index += 1;
			let target_file = my_path.join(&info.path);
			if let Some(existing) = local_cache.get(&info.path) {
				if existing.eq_ignore_ascii_case(&info.hash) {
					continue;
				}
			} else {
				if exists(&target_file)? {
					let local_hash = calculate_file_hash(&target_file)?;
					if local_hash.eq_ignore_ascii_case(&info.hash) {
						local_cache.insert(info.path.clone(), local_hash);
						continue;
					}
				}
			}

			let parent_path = target_file.parent().unwrap();
			if !exists(parent_path)? {
				std::fs::create_dir_all(parent_path)?;
			}

			println!("Downloading {:?} -> {:?}", info.path, info.hash);

			let req = client.get(info.url.clone());
			let res = req.send().await?;
			let mut file = File::create(target_file)?;
			file.write_all(res.bytes().await?.as_ref())?;
			local_cache.insert(info.path.clone(), info.hash.clone());
		}

		write_cache_to_disk(local_cache)?;
	}

	#[cfg(target_os = "windows")]
	game::launch(get_my_dir()?.join("Binaries/TERA.exe")).await?;

	Ok(())
}

async fn login(username: String, password: String) -> Result<()> {
	let client = reqwest::Client::new();

	let req = client.post(get_config()?.login);
	let res = req.form(&vec![("login", username), ("password", password)]).send().await?;

	let token_path = get_login_token_path()?;
	println!("Saving {:?}", token_path);

	let mut file = File::create(token_path)?;
	file.write_all(res.bytes().await?.as_ref())?;

	Ok(())
}
