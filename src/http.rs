use anyhow::{Context, Result};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// HTTP client configuration for download operations
#[derive(Debug, Clone)]
pub struct HttpConfig {
	/// Maximum number of concurrent downloads
	pub max_concurrent_downloads: usize,
	/// Timeout for individual requests
	pub request_timeout: Duration,
	/// Maximum number of retries for failed requests
	pub max_retries: u8,
	/// Backoff multiplier for retries
	pub retry_backoff_multiplier: f32,
}

impl Default for HttpConfig {
	fn default() -> Self {
		Self {
			max_concurrent_downloads: 4,
			request_timeout: Duration::from_secs(30),
			max_retries: 3,
			retry_backoff_multiplier: 1.5,
		}
	}
}

/// HTTP client wrapper with connection pooling and concurrency control
pub struct HttpClient {
	client: Client,
	semaphore: Arc<Semaphore>,
	config: HttpConfig,
}

impl HttpClient {
	/// Create a new HTTP client with the given configuration
	pub fn new(config: HttpConfig) -> Result<Self> {
		let client = Client::builder()
			.timeout(config.request_timeout)
			.pool_max_idle_per_host(config.max_concurrent_downloads)
			.danger_accept_invalid_certs(true)
			.build()
			.context("Failed to create HTTP client")?;

		let semaphore = Arc::new(Semaphore::new(config.max_concurrent_downloads));

		Ok(Self {
			client,
			semaphore,
			config,
		})
	}

	/// Get the underlying reqwest client
	pub fn client(&self) -> &Client {
		&self.client
	}

	/// Acquire a permit for concurrent operations
	pub async fn acquire_permit(&self) -> Result<tokio::sync::SemaphorePermit<'_>> {
		self.semaphore.acquire().await.context("Failed to acquire download permit")
	}

	/// Download a file with retries and exponential backoff
	pub async fn download_with_retries(&self, url: &str) -> Result<reqwest::Response> {
		let mut retries = 0;
		let mut backoff = Duration::from_millis(500);

		loop {
			debug!("Downloading {} (attempt {})", url, retries + 1);

			match self.client.get(url).send().await {
				Ok(response) => {
					if response.status().is_success() {
						info!("Successfully downloaded {}", url);
						return Ok(response);
					} else {
						warn!("HTTP error {} for {}", response.status(), url);
						if retries >= self.config.max_retries {
							return Err(anyhow::anyhow!(
								"Failed to download {} after {} attempts: HTTP {}",
								url,
								retries + 1,
								response.status()
							));
						}
					}
				}
				Err(e) => {
					error!("Network error downloading {}: {}", url, e);
					if retries >= self.config.max_retries {
						return Err(anyhow::anyhow!("Failed to download {} after {} attempts: {}", url, retries + 1, e));
					}
				}
			}

			retries += 1;
			debug!("Retrying {} in {:?}", url, backoff);
			tokio::time::sleep(backoff).await;
			backoff = Duration::from_millis((backoff.as_millis() as f32 * self.config.retry_backoff_multiplier) as u64);
		}
	}

	/// Get the maximum number of concurrent downloads
	pub fn max_concurrent_downloads(&self) -> usize {
		self.config.max_concurrent_downloads
	}
}
