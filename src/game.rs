// largely based off tera-rust-launcher

use crate::util::*;

use anyhow::Result;

use winapi::shared::minwindef::{BOOL, LPARAM, LRESULT, TRUE, UINT, WPARAM};
use winapi::shared::windef::HWND;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::winuser::{
	COPYDATASTRUCT, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, EnumWindows, GetClassInfoExW, GetClassNameW,
	GetMessageW, PostQuitMessage, RegisterClassExW, SendMessageW, TranslateMessage, UnregisterClassW, WM_COPYDATA, WNDCLASSEXW,
};

use bytemuck::{ByteEq, ByteHash, Pod, Zeroable, try_cast_slice};
use std::ffi::OsStr;
use std::fs::{File, remove_file};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr::null_mut;
use std::slice;

pub async fn launch(exe_path: PathBuf) -> Result<i32> {
	let client = reqwest::Client::new();

	let config = get_config()?;
	let req = client.get(config.world);
	let res = req.send().await?;

	let server_path = get_server_path()?;

	let mut file = File::create(server_path)?;
	file.write_all(res.bytes().await?.as_ref())?;

	tokio::task::spawn_blocking(move || create_and_run_game_window());

	let mut child = Command::new(exe_path).arg(format!("-LANGUAGEEXT={}", config.lang.unwrap_or("EUR".to_string())).to_string()).spawn()?;

	let pid = child.id();
	println!("Game process spawned with PID: {}", pid);

	let status = child.wait()?;
	println!("Game process exited with status: {:?}", status.code());

	Ok(status.code().unwrap_or(0))
}

fn to_wstring(s: &str) -> Vec<u16> {
	OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

#[repr(usize)]
#[derive(Hash, PartialEq, Eq, Ord, PartialOrd, Debug, Copy, Clone)]
enum S1Event {
	AccountNameRequest = 1,
	AccountNameResponse = 2,
	SessionTicketRequest = 3,
	SessionTicketResponse = 4,
	ServerListRequest = 5,
	ServerListResponse = 6,
	EnterLobbyOrWorld = 7,
	CreateRoomRequest = 8,
	CreateRoomResponse = 9,
	JoinRoomRequest = 10,
	JoinRoomResponse = 11,
	LeaveRoomRequest = 12,
	LeaveRoomResponse = 13,
	SetVolumeCommand = 19,
	SetMicrophoneCommand = 20,
	SilenceUserCommand = 21,
	OpenWebsiteCommand = 25,
	WebUrlRequest = 26,
	WebUrlResponse = 27,
	GameStart = 1000,
	EnteredIntoCinematic = 1001,
	EnteredServerList = 1002,
	EnteringLobby = 1003,
	EnteredLobby = 1004,
	EnteringCharacterCreation = 1005,
	LeftLobby = 1006,
	DeletedCharacter = 1007,
	CanceledCharacterCreation = 1008,
	EnteredCharacterCreation = 1009,
	CreatedCharacter = 1010,
	EnteredWorld = 1011,
	FinishedLoadingScreen = 1012,
	LeftWorld = 1013,
	MountedPegasus = 1014,
	DismountedPegasus = 1015,
	ChangedChannel = 1016,
	GameExit = 1020,
	GameCrash = 1021,
	AntiCheatStarting = 1022,
	AntiCheatStarted = 1023,
	AntiCheatError = 1024,
	OpenSupportWebsiteCommand = 1025,
	Other(usize),
}

impl Into<usize> for S1Event {
	fn into(self) -> usize {
		match self {
			S1Event::Other(i) => i,
			S1Event::AccountNameRequest => 1,
			S1Event::AccountNameResponse => 2,
			S1Event::SessionTicketRequest => 3,
			S1Event::SessionTicketResponse => 4,
			S1Event::ServerListRequest => 5,
			S1Event::ServerListResponse => 6,
			S1Event::EnterLobbyOrWorld => 7,
			S1Event::CreateRoomRequest => 8,
			S1Event::CreateRoomResponse => 9,
			S1Event::JoinRoomRequest => 10,
			S1Event::JoinRoomResponse => 11,
			S1Event::LeaveRoomRequest => 12,
			S1Event::LeaveRoomResponse => 13,
			S1Event::SetVolumeCommand => 19,
			S1Event::SetMicrophoneCommand => 20,
			S1Event::SilenceUserCommand => 21,
			S1Event::OpenWebsiteCommand => 25,
			S1Event::WebUrlRequest => 26,
			S1Event::WebUrlResponse => 27,
			S1Event::GameStart => 1000,
			S1Event::EnteredIntoCinematic => 1001,
			S1Event::EnteredServerList => 1002,
			S1Event::EnteringLobby => 1003,
			S1Event::EnteredLobby => 1004,
			S1Event::EnteringCharacterCreation => 1005,
			S1Event::LeftLobby => 1006,
			S1Event::DeletedCharacter => 1007,
			S1Event::CanceledCharacterCreation => 1008,
			S1Event::EnteredCharacterCreation => 1009,
			S1Event::CreatedCharacter => 1010,
			S1Event::EnteredWorld => 1011,
			S1Event::FinishedLoadingScreen => 1012,
			S1Event::LeftWorld => 1013,
			S1Event::MountedPegasus => 1014,
			S1Event::DismountedPegasus => 1015,
			S1Event::ChangedChannel => 1016,
			S1Event::GameExit => 1020,
			S1Event::GameCrash => 1021,
			S1Event::AntiCheatStarting => 1022,
			S1Event::AntiCheatStarted => 1023,
			S1Event::AntiCheatError => 1024,
			S1Event::OpenSupportWebsiteCommand => 1025,
		}
	}
}

impl Into<S1Event> for usize {
	fn into(self) -> S1Event {
		match self {
			1 => S1Event::AccountNameRequest,
			2 => S1Event::AccountNameResponse,
			3 => S1Event::SessionTicketRequest,
			4 => S1Event::SessionTicketResponse,
			5 => S1Event::ServerListRequest,
			6 => S1Event::ServerListResponse,
			7 => S1Event::EnterLobbyOrWorld,
			8 => S1Event::CreateRoomRequest,
			9 => S1Event::CreateRoomResponse,
			10 => S1Event::JoinRoomRequest,
			11 => S1Event::JoinRoomResponse,
			12 => S1Event::LeaveRoomRequest,
			13 => S1Event::LeaveRoomResponse,
			19 => S1Event::SetVolumeCommand,
			20 => S1Event::SetMicrophoneCommand,
			21 => S1Event::SilenceUserCommand,
			25 => S1Event::OpenWebsiteCommand,
			26 => S1Event::WebUrlRequest,
			27 => S1Event::WebUrlResponse,
			1000 => S1Event::GameStart,
			1001 => S1Event::EnteredIntoCinematic,
			1002 => S1Event::EnteredServerList,
			1003 => S1Event::EnteringLobby,
			1004 => S1Event::EnteredLobby,
			1005 => S1Event::EnteringCharacterCreation,
			1006 => S1Event::LeftLobby,
			1007 => S1Event::DeletedCharacter,
			1008 => S1Event::CanceledCharacterCreation,
			1009 => S1Event::EnteredCharacterCreation,
			1010 => S1Event::CreatedCharacter,
			1011 => S1Event::EnteredWorld,
			1012 => S1Event::FinishedLoadingScreen,
			1013 => S1Event::LeftWorld,
			1014 => S1Event::MountedPegasus,
			1015 => S1Event::DismountedPegasus,
			1016 => S1Event::ChangedChannel,
			1020 => S1Event::GameExit,
			1021 => S1Event::GameCrash,
			1022 => S1Event::AntiCheatStarting,
			1023 => S1Event::AntiCheatStarted,
			1024 => S1Event::AntiCheatError,
			1025 => S1Event::OpenSupportWebsiteCommand,
			_ => S1Event::Other(self),
		}
	}
}

#[repr(u16)]
#[derive(Hash, PartialEq, Eq, Ord, PartialOrd, Debug, Copy, Clone)]
enum S1ExitReason {
	Success = 0,
	Manual = 16,
	InvalidSession = 257,
	AlreadyOnline = 262,
	Other(u16),
}

#[derive(Copy, Clone, Pod, Zeroable, ByteEq, ByteHash)]
#[repr(C)]
pub struct S1ExitMessage {
	#[bytemuck]
	pub len: u32,
	#[bytemuck]
	pub code: u32,
	#[bytemuck]
	pub reason: u16,
	#[bytemuck]
	pub reason_msg_id: u16,
}

impl Into<S1ExitReason> for u16 {
	fn into(self) -> S1ExitReason {
		match self {
			0 => S1ExitReason::Success,
			16 => S1ExitReason::Manual,
			257 => S1ExitReason::InvalidSession,
			262 => S1ExitReason::AlreadyOnline,
			_ => S1ExitReason::Other(self),
		}
	}
}

unsafe extern "system" fn wnd_proc(h_wnd: HWND, msg: UINT, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
	match msg {
		WM_COPYDATA => {
			let copy_data = unsafe { &*(l_param as *const COPYDATASTRUCT) };
			let event_id: S1Event = copy_data.dwData.into();
			let payload = if copy_data.cbData > 0 {
				unsafe { slice::from_raw_parts(copy_data.lpData as *const u8, copy_data.cbData as usize) }
			} else {
				&[]
			};
			println!("RX Event: {:?} ({:?}), Payload: {:02x?}", event_id, copy_data.dwData, payload);

			match event_id {
				S1Event::AccountNameRequest => handle_account_name_request(w_param, h_wnd),
				S1Event::SessionTicketRequest => handle_session_ticket_request(w_param, h_wnd),
				S1Event::ServerListRequest => handle_server_list_request(w_param, h_wnd),
				S1Event::EnterLobbyOrWorld => handle_enter_lobby_or_world(payload),
				S1Event::GameExit => handle_game_exit(payload).map_err(|e| eprintln!("{:?}", e)).unwrap_or(()),
				S1Event::GameCrash => handle_game_crash(payload),
				_ => {}
			};
			1
		}
		_ => unsafe { DefWindowProcW(h_wnd, msg, w_param, l_param) },
	}
}

fn handle_game_exit(payload: &[u8]) -> Result<()> {
	if payload.len() < 0xc {
		return Ok(());
	}

	let rsp: &S1ExitMessage = if let Ok(rsps) = try_cast_slice::<u8, S1ExitMessage>(payload)
		&& let Some(rsp) = rsps.first()
	{
		rsp
	} else {
		return Ok(());
	};
	let reason: S1ExitReason = rsp.reason.into();
	println!("exited! code: {:?}, reason: {:?}, msg: {:?}", rsp.code, reason, rsp.reason_msg_id);

	match reason {
		S1ExitReason::InvalidSession => {
			println!("session is invalid, deleting auth file!");
			remove_file(get_login_token_path()?)?;
		}
		_ => {}
	}

	unsafe { Ok(PostQuitMessage(rsp.code as i32)) }
}

fn handle_game_crash(payload: &[u8]) {
	let mut u16vec: Vec<u16> = payload.chunks_exact(2).map(|c| u16::from_le_bytes(c.try_into().unwrap())).collect();
	u16vec.pop_if(|last| *last == 0u16);
	let crash_msg = String::from_utf16_lossy(u16vec.as_ref());
	eprintln!("crashed!");
	eprintln!("{}", crash_msg);
	unsafe { PostQuitMessage(-1) }
}

fn handle_account_name_request(recipient: WPARAM, sender: HWND) {
	let account_name = load_auth_from_disk().expect("Failed to load auth from disk").user_no.expect("No user no");
	println!("Account Name Request - Sending: {}", account_name);
	let account_name_utf16: Vec<u8> = account_name.to_string().encode_utf16().flat_map(|c| c.to_le_bytes().to_vec()).collect();
	send_response_message(recipient, sender, S1Event::AccountNameResponse, &account_name_utf16);
}

fn handle_session_ticket_request(recipient: WPARAM, sender: HWND) {
	let session_ticket = load_auth_from_disk().expect("Failed to load auth from disk").auth_key.expect("No auth key");
	println!("Session Ticket Request - Sending: {}", session_ticket);
	send_response_message(recipient, sender, S1Event::SessionTicketResponse, &session_ticket.into_bytes());
}

fn handle_server_list_request(recipient: WPARAM, sender: HWND) {
	let server_list_data = load_server_from_disk().expect("Failed to get server list data");
	send_response_message(recipient, sender, S1Event::ServerListResponse, &server_list_data);
}

fn handle_enter_lobby_or_world(payload: &[u8]) {
	if payload.is_empty() {
		println!("Entered lobby");
	} else {
		let mut u16vec: Vec<u16> = payload.chunks_exact(2).map(|c| u16::from_le_bytes(c.try_into().unwrap())).collect();
		u16vec.pop_if(|last| *last == 0u16);
		let char_name = String::from_utf16_lossy(u16vec.as_ref());
		println!("Entered world with character \"{}\"", char_name);
	}
}

extern "system" fn enum_window_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
	let mut class_name: [u16; 256] = [0; 256];
	let len = unsafe { GetClassNameW(hwnd, class_name.as_mut_ptr(), 256) as usize };
	let class_name = &class_name[..len];

	let search_class = unsafe { slice::from_raw_parts(lparam as *const u16, 256) };
	let search_len = search_class.iter().position(|&c| c == 0).unwrap_or(256);
	let search_class = &search_class[..search_len];

	if class_name.starts_with(search_class) {
		unsafe { DestroyWindow(hwnd) };
	}
	TRUE
}

fn create_and_run_game_window() {
	let launcher_class_name = "LAUNCHER_CLASS";
	let launcher_window_title = "LAUNCHER_WINDOW";
	let class_name = to_wstring(launcher_class_name);
	let window_name = to_wstring(launcher_window_title);
	let wnd_class = WNDCLASSEXW {
		cbSize: size_of::<WNDCLASSEXW>() as u32,
		style: 0,
		lpfnWndProc: Some(wnd_proc),
		cbClsExtra: 0,
		cbWndExtra: 0,
		hInstance: unsafe { GetModuleHandleW(null_mut()) },
		hIcon: null_mut(),
		hCursor: null_mut(),
		hbrBackground: null_mut(),
		lpszMenuName: null_mut(),
		lpszClassName: class_name.as_ptr(),
		hIconSm: null_mut(),
	};

	let atom = unsafe { RegisterClassExW(&wnd_class) };
	if atom == 0 {
		eprintln!("Failed to register window class");
		return;
	}

	let hwnd = unsafe {
		CreateWindowExW(
			0,
			class_name.as_ptr(),
			window_name.as_ptr(),
			0,
			0,
			0,
			0,
			0,
			null_mut(),
			null_mut(),
			GetModuleHandleW(null_mut()),
			null_mut(),
		)
	};

	if hwnd.is_null() {
		eprintln!("Failed to create window");
		unsafe {
			UnregisterClassW(class_name.as_ptr(), GetModuleHandleW(null_mut()));
		}
		return;
	}

	println!("Window created with HWND: {:?}", hwnd);

	let mut msg = unsafe { std::mem::zeroed() };
	unsafe {
		while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
			if msg.message == 0x401 {
				break;
			}
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
		DestroyWindow(hwnd);
		UnregisterClassW(class_name.as_ptr(), GetModuleHandleW(null_mut()));
	}
	let mut wcex: WNDCLASSEXW = unsafe { std::mem::zeroed() };
	wcex.cbSize = size_of::<WNDCLASSEXW>() as u32;

	unsafe {
		EnumWindows(Some(enum_window_proc), class_name.as_ptr() as LPARAM);

		if GetClassInfoExW(GetModuleHandleW(null_mut()), class_name.as_ptr(), &mut wcex) != 0 {
			UnregisterClassW(class_name.as_ptr(), GetModuleHandleW(null_mut()));
		}
	}
}

fn send_response_message(recipient: WPARAM, sender: HWND, game_event: S1Event, payload: &[u8]) {
	let op: usize = game_event.into();
	println!("TX Event: {:?} ({:?}), Payload: {:02x?}", game_event, op, payload);
	let copy_data = COPYDATASTRUCT {
		dwData: op,
		cbData: payload.len() as u32,
		lpData: payload.as_ptr() as *mut _,
	};

	unsafe {
		SendMessageW(recipient as HWND, WM_COPYDATA, sender as WPARAM, &copy_data as *const _ as LPARAM);
	}
}
