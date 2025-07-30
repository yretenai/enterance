# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**enterance** is a minimal TERA Launcher replacement written in Rust that serves as a game launcher handling authentication, file updates, and game process management for the TERA online game.

## Essential Commands

### Build and Development

- `cargo build` - Compile the project
- `cargo build --release` - Compile optimized release build
- `cargo run` - Build and run the application
- `cargo check` - Check for compilation errors without building
- `cargo test` - Run tests
- `cargo fmt --all` - Format all Rust code according to project style
- `cargo clean` - Clean build artifacts

### Prerequisites

- Requires Protocol Buffers compiler (`protoc`) for building
- Build script automatically compiles `serverlist.proto` during build

## Architecture Overview

### Main Components

**main.rs** - Core launcher logic:

- Config management (loads `enterance.ini` TOML file)
- Authentication flow with username/password
- File updater with SHA256 hash verification
- Cache system for efficient incremental updates
- Cross-platform entry point with platform-specific execution

**game.rs** - Windows-only game launcher:

- TERA game process spawning and monitoring
- Windows IPC via WM_COPYDATA messages
- S1 protocol implementation for TERA communication
- Server list management and authentication
- Game event handling (login, crashes, exits)

**util.rs** - Shared utilities:

- Configuration structures (Config, LoginResponse, FileInfo, HashFile)
- File system operations and path management
- Cross-platform abstractions
- JSON/TOML serialization helpers
- Network data structures and protobuf conversion

**serverlist.proto** - Protocol buffer definitions for server communication

### Key Data Flow

1. Load config from `enterance.ini` → Authentication → File verification/updates → Game launch (Windows only)
2. Maintains local file hash cache for efficient updates
3. Uses protobuf for server communication and JSON for local data

### Configuration

Application expects `enterance.ini` with:

- `update`: File update manifest URL
- `login`: Authentication endpoint URL
- `world`: Server list endpoint URL
- `path`: Game executable path (default: "Binaries/TERA.exe")
- `lang`: Language setting (default: "EUR")

## Platform Considerations

- **Windows**: Full functionality including game launching
- **Unix/Linux**: Config and file operations only (game launching disabled)
- Uses `winapi` for Windows-specific functionality
- Uses `termion` for Unix terminal handling

## Development Notes

- **Rust Edition**: 2024
- **Formatting**: Hard tabs, 140 character width (see `.rustfmt.toml`)
- **Error Handling**: Uses `anyhow` for comprehensive error management
- **Async**: Built on `tokio` runtime
- **Security**: SHA256 file integrity verification throughout
- **Network**: `reqwest` for HTTP operations with retry logic
