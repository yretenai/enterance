use anyhow::Context;
use std::fmt;

#[derive(Debug)]
#[allow(dead_code)]
pub enum EnteranceError {
	ConfigNotFound,
	ConfigInvalid(String),
	NetworkError(String),
	AuthenticationFailed(String),
	FileSystemError(String),
	ValidationError(String),
}

impl fmt::Display for EnteranceError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			EnteranceError::ConfigNotFound => {
				writeln!(f, "Configuration file not found")?;
				writeln!(f)?;
				writeln!(f, "To fix this issue:")?;
				writeln!(f, "   1. Run 'enterance config --init' to create a new configuration")?;
				write!(f, "   2. Or manually create 'enterance.ini' in the same directory as the executable")
			}
			EnteranceError::ConfigInvalid(msg) => {
				writeln!(f, "Configuration file is invalid: {msg}")?;
				writeln!(f)?;
				writeln!(f, "To fix this issue:")?;
				writeln!(f, "   1. Check the configuration file format (should be TOML)")?;
				writeln!(f, "   2. Ensure all required fields are present: update, login, world")?;
				writeln!(f, "   3. Verify URLs are properly formatted")?;
				write!(f, "   4. Run 'enterance config --init' to create a fresh configuration")
			}
			EnteranceError::NetworkError(msg) => {
				writeln!(f, "Network error: {msg}")?;
				writeln!(f)?;
				writeln!(f, "To fix this issue:")?;
				writeln!(f, "   1. Check your internet connection")?;
				writeln!(f, "   2. Verify the server URLs in your configuration")?;
				writeln!(f, "   3. Check if the servers are currently online")?;
				write!(f, "   4. Try again in a few minutes")
			}
			EnteranceError::AuthenticationFailed(msg) => {
				writeln!(f, "Authentication failed: {msg}")?;
				writeln!(f)?;
				writeln!(f, "To fix this issue:")?;
				writeln!(f, "   1. Verify your username and password are correct")?;
				writeln!(f, "   2. Check if your account is active")?;
				writeln!(f, "   3. Clear stored credentials with 'enterance clean --auth'")?;
				write!(f, "   4. Try logging in again with 'enterance login'")
			}
			EnteranceError::FileSystemError(msg) => {
				writeln!(f, "File system error: {msg}")?;
				writeln!(f)?;
				writeln!(f, "To fix this issue:")?;
				writeln!(f, "   1. Check if you have sufficient disk space")?;
				writeln!(f, "   2. Verify write permissions to the installation directory")?;
				writeln!(f, "   3. Check if any files are in use by other programs")?;
				write!(f, "   4. Try running as administrator/root if necessary")
			}
			EnteranceError::ValidationError(msg) => {
				writeln!(f, "Validation error: {msg}")?;
				writeln!(f)?;
				writeln!(f, "To fix this issue:")?;
				writeln!(f, "   1. Check the input format and try again")?;
				writeln!(f, "   2. Ensure all required fields are provided")?;
				write!(f, "   3. Refer to the documentation for correct format")
			}
		}
	}
}

impl std::error::Error for EnteranceError {}

#[allow(dead_code)]
pub trait ErrorContextExt<T> {
	fn with_config_context(self) -> Result<T, anyhow::Error>;
	fn with_network_context(self, operation: &str) -> Result<T, anyhow::Error>;
	fn with_auth_context(self) -> Result<T, anyhow::Error>;
	fn with_fs_context(self, operation: &str) -> Result<T, anyhow::Error>;
}

impl<T, E> ErrorContextExt<T> for Result<T, E>
where
	E: std::error::Error + Send + Sync + 'static,
{
	fn with_config_context(self) -> Result<T, anyhow::Error> {
		self.context("Configuration error occurred")
	}

	fn with_network_context(self, operation: &str) -> Result<T, anyhow::Error> {
		self.with_context(|| format!("Network error during {operation}"))
	}

	fn with_auth_context(self) -> Result<T, anyhow::Error> {
		self.context("Authentication error occurred")
	}

	fn with_fs_context(self, operation: &str) -> Result<T, anyhow::Error> {
		self.with_context(|| format!("File system error during {operation}"))
	}
}
