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

use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr::null_mut;
use std::slice;

pub async fn launch(exe_path: PathBuf) -> Result<i32> {
	let client = reqwest::Client::new();

	let req = client.get(get_config()?.world);
	let res = req.send().await?;

	let server_path = get_server_path()?;

	let mut file = File::create(server_path)?;
	file.write_all(res.bytes().await?.as_ref())?;

	tokio::task::spawn_blocking(move || unsafe { create_and_run_game_window() });

	let mut child = Command::new(exe_path).arg("-LANGUAGEEXT=EUR".to_string()).spawn()?;

	let pid = child.id();
	println!("Game process spawned with PID: {}", pid);

	let status = child.wait()?;
	println!("Game process exited with status: {:?}", status.code());

	Ok(status.code().unwrap_or(0))
}

fn to_wstring(s: &str) -> Vec<u16> {
	OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

#[derive(Hash, PartialEq, Eq, Ord, PartialOrd, Debug, Copy, Clone)]
#[repr(usize)]
enum S1Event {
	AccountNameRequest = 0x1,
	AccountNameResponse = 0x2,
	SessionTicketRequest = 0x3,
	SessionTicketResponse = 0x4,
	ServerListRequest = 0x5,
	ServerListResponse = 0x6,
	EnterLobbyOrWorldNotification = 0x7,
	CreateRoomRequest = 0x8,
	CreateRoomResponse = 0x9,
	JoinRoomRequest = 0xa,
	JoinRoomResponse = 0xb,
	LeaveRoomRequest = 0xc,
	LeaveRoomResponse = 0xd,
	SetVolumeCommand = 0x13,
	SetMicrophoneCommand = 0x14,
	SilenceUserCommand = 0x15,
	OpenWebsiteCommand = 0x19,
	WebUrlRequest = 0x1a,
	WebUrlResponse = 0x1b,
	GameStartNotification = 0x3e8,
	EnteredIntoCinematicNotification = 0x3e9,
	EnteredServerListNotification = 0x3ea,
	EnteringLobbyNotification = 0x3eb,
	EnteredLobbyNotification = 0x3ec,
	EnteringCharacterCreationNotification = 0x3ed,
	LeftLobbyNotification = 0x3ee,
	DeletedCharacterNotification = 0x3ef,
	CanceledCharacterCreationNotification = 0x3f0,
	EnteredCharacterCreationNotification = 0x3f1,
	CreatedCharacterNotification = 0x3f2,
	EnteredWorldNotification = 0x3f3,
	FinishedLoadingScreenNotification = 0x3f4,
	LeftWorldNotification = 0x3f5,
	MountedPegasusNotification = 0x3f6,
	DismountedPegasusNotification = 0x3f7,
	ChangedChannelNotification = 0x3f8,
	GameExitNotification = 0x3fc,
	GameCrashNotification = 0x3fd,
	AntiCheatStartingNotification = 0x3fe,
	AntiCheatStartedNotification = 0x3ff,
	AntiCheatErrorNotification = 0x400,
	OpenSupportWebsiteCommand = 0x401,
	Other(usize),
}

impl Into<usize> for S1Event {
	fn into(self) -> usize {
		match self {
			S1Event::Other(i) => i,
			S1Event::AccountNameRequest => 0x1,
			S1Event::AccountNameResponse => 0x2,
			S1Event::SessionTicketRequest => 0x3,
			S1Event::SessionTicketResponse => 0x4,
			S1Event::ServerListRequest => 0x5,
			S1Event::ServerListResponse => 0x6,
			S1Event::EnterLobbyOrWorldNotification => 0x7,
			S1Event::CreateRoomRequest => 0x8,
			S1Event::CreateRoomResponse => 0x9,
			S1Event::JoinRoomRequest => 0xa,
			S1Event::JoinRoomResponse => 0xb,
			S1Event::LeaveRoomRequest => 0xc,
			S1Event::LeaveRoomResponse => 0xd,
			S1Event::SetVolumeCommand => 0x13,
			S1Event::SetMicrophoneCommand => 0x14,
			S1Event::SilenceUserCommand => 0x15,
			S1Event::OpenWebsiteCommand => 0x19,
			S1Event::WebUrlRequest => 0x1a,
			S1Event::WebUrlResponse => 0x1b,
			S1Event::GameStartNotification => 0x3e8,
			S1Event::EnteredIntoCinematicNotification => 0x3e9,
			S1Event::EnteredServerListNotification => 0x3ea,
			S1Event::EnteringLobbyNotification => 0x3eb,
			S1Event::EnteredLobbyNotification => 0x3ec,
			S1Event::EnteringCharacterCreationNotification => 0x3ed,
			S1Event::LeftLobbyNotification => 0x3ee,
			S1Event::DeletedCharacterNotification => 0x3ef,
			S1Event::CanceledCharacterCreationNotification => 0x3f0,
			S1Event::EnteredCharacterCreationNotification => 0x3f1,
			S1Event::CreatedCharacterNotification => 0x3f2,
			S1Event::EnteredWorldNotification => 0x3f3,
			S1Event::FinishedLoadingScreenNotification => 0x3f4,
			S1Event::LeftWorldNotification => 0x3f5,
			S1Event::MountedPegasusNotification => 0x3f6,
			S1Event::DismountedPegasusNotification => 0x3f7,
			S1Event::ChangedChannelNotification => 0x3f8,
			S1Event::GameExitNotification => 0x3fc,
			S1Event::GameCrashNotification => 0x3fd,
			S1Event::AntiCheatStartingNotification => 0x3fe,
			S1Event::AntiCheatStartedNotification => 0x3ff,
			S1Event::AntiCheatErrorNotification => 0x400,
			S1Event::OpenSupportWebsiteCommand => 0x401,
		}
	}
}

impl Into<S1Event> for usize {
	fn into(self) -> S1Event {
		match self {
			0x1 => S1Event::AccountNameRequest,
			0x2 => S1Event::AccountNameResponse,
			0x3 => S1Event::SessionTicketRequest,
			0x4 => S1Event::SessionTicketResponse,
			0x5 => S1Event::ServerListRequest,
			0x6 => S1Event::ServerListResponse,
			0x7 => S1Event::EnterLobbyOrWorldNotification,
			0x8 => S1Event::CreateRoomRequest,
			0x9 => S1Event::CreateRoomResponse,
			0xa => S1Event::JoinRoomRequest,
			0xb => S1Event::JoinRoomResponse,
			0xc => S1Event::LeaveRoomRequest,
			0xd => S1Event::LeaveRoomResponse,
			0x13 => S1Event::SetVolumeCommand,
			0x14 => S1Event::SetMicrophoneCommand,
			0x15 => S1Event::SilenceUserCommand,
			0x19 => S1Event::OpenWebsiteCommand,
			0x1a => S1Event::WebUrlRequest,
			0x1b => S1Event::WebUrlResponse,
			0x3e8 => S1Event::GameStartNotification,
			0x3e9 => S1Event::EnteredIntoCinematicNotification,
			0x3ea => S1Event::EnteredServerListNotification,
			0x3eb => S1Event::EnteringLobbyNotification,
			0x3ec => S1Event::EnteredLobbyNotification,
			0x3ed => S1Event::EnteringCharacterCreationNotification,
			0x3ee => S1Event::LeftLobbyNotification,
			0x3ef => S1Event::DeletedCharacterNotification,
			0x3f0 => S1Event::CanceledCharacterCreationNotification,
			0x3f1 => S1Event::EnteredCharacterCreationNotification,
			0x3f2 => S1Event::CreatedCharacterNotification,
			0x3f3 => S1Event::EnteredWorldNotification,
			0x3f4 => S1Event::FinishedLoadingScreenNotification,
			0x3f5 => S1Event::LeftWorldNotification,
			0x3f6 => S1Event::MountedPegasusNotification,
			0x3f7 => S1Event::DismountedPegasusNotification,
			0x3f8 => S1Event::ChangedChannelNotification,
			0x3fc => S1Event::GameExitNotification,
			0x3fd => S1Event::GameCrashNotification,
			0x3fe => S1Event::AntiCheatStartingNotification,
			0x3ff => S1Event::AntiCheatStartedNotification,
			0x400 => S1Event::AntiCheatErrorNotification,
			0x401 => S1Event::OpenSupportWebsiteCommand,
			_ => S1Event::Other(self),
		}
	}
}

unsafe extern "system" fn wnd_proc(h_wnd: HWND, msg: UINT, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
	match msg {
		WM_COPYDATA => {
			unsafe {
				let copy_data = &*(l_param as *const COPYDATASTRUCT);
				let event_id: S1Event = copy_data.dwData.into();
				let payload = if copy_data.cbData > 0 {
					slice::from_raw_parts(copy_data.lpData as *const u8, copy_data.cbData as usize)
				} else {
					&[]
				};
				println!("RX Event: {:?} ({:?}), Payload: {:?}", event_id, copy_data.dwData, payload);

				match event_id {
					S1Event::AccountNameRequest => handle_account_name_request(w_param, h_wnd),
					S1Event::SessionTicketRequest => handle_session_ticket_request(w_param, h_wnd),
					S1Event::ServerListRequest => handle_server_list_request(w_param, h_wnd),
					S1Event::EnterLobbyOrWorldNotification => handle_enter_lobby_or_world(payload),
					S1Event::GameExitNotification => PostQuitMessage(0),
					S1Event::GameCrashNotification => PostQuitMessage(1),
					_ => {}
				}
			}
			1
		}
		_ => unsafe { DefWindowProcW(h_wnd, msg, w_param, l_param) },
	}
}

unsafe fn handle_account_name_request(recipient: WPARAM, sender: HWND) {
	let account_name = load_auth_from_disk().expect("Failed to load auth from disk").user_no;
	println!("Account Name Request - Sending: {}", account_name);
	let account_name_utf16: Vec<u8> = account_name.to_string().encode_utf16().flat_map(|c| c.to_le_bytes().to_vec()).collect();
	unsafe {
		send_response_message(recipient, sender, S1Event::AccountNameResponse, &account_name_utf16);
	}
}

unsafe fn handle_session_ticket_request(recipient: WPARAM, sender: HWND) {
	let session_ticket = load_auth_from_disk().expect("Failed to load auth from disk").auth_key;
	println!("Session Ticket Request - Sending: {}", session_ticket);
	unsafe {
		send_response_message(recipient, sender, S1Event::SessionTicketResponse, &session_ticket.into_bytes());
	}
}

unsafe fn handle_server_list_request(recipient: WPARAM, sender: HWND) {
	let server_list_data = load_server_from_disk().expect("Failed to get server list data");
	unsafe {
		send_response_message(recipient, sender, S1Event::ServerListResponse, &server_list_data);
	}
}

fn handle_enter_lobby_or_world(payload: &[u8]) {
	if payload.is_empty() {
		println!("Entered lobby");
	} else {
		let mut u16vec: Vec<u16> = payload.chunks_exact(2).map(|c| u16::from_le_bytes(c.try_into().unwrap())).collect();
		u16vec.pop_if(|last| *last == 0u16);
		let char_name = String::from_utf16_lossy(u16vec.as_ref());
		println!("Entered world: Character \"{}\"", char_name);
	}
}

unsafe extern "system" fn enum_window_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
	let mut class_name: [u16; 256] = [0; 256];
	unsafe {
		let len = GetClassNameW(hwnd, class_name.as_mut_ptr(), 256) as usize;
		let class_name = &class_name[..len];

		let search_class = slice::from_raw_parts(lparam as *const u16, 256);
		let search_len = search_class.iter().position(|&c| c == 0).unwrap_or(256);
		let search_class = &search_class[..search_len];

		if class_name.starts_with(search_class) {
			DestroyWindow(hwnd);
		}
	}
	TRUE
}

unsafe fn create_and_run_game_window() {
	let launcher_class_name = "LAUNCHER_CLASS";
	let launcher_window_title = "LAUNCHER_WINDOW";
	let class_name = to_wstring(launcher_class_name);
	let window_name = to_wstring(launcher_window_title);
	unsafe {
		let wnd_class = WNDCLASSEXW {
			cbSize: size_of::<WNDCLASSEXW>() as u32,
			style: 0,
			lpfnWndProc: Some(wnd_proc),
			cbClsExtra: 0,
			cbWndExtra: 0,
			hInstance: GetModuleHandleW(null_mut()),
			hIcon: null_mut(),
			hCursor: null_mut(),
			hbrBackground: null_mut(),
			lpszMenuName: null_mut(),
			lpszClassName: class_name.as_ptr(),
			hIconSm: null_mut(),
		};

		let atom = RegisterClassExW(&wnd_class);
		if atom == 0 {
			eprintln!("Failed to register window class");
			return;
		}

		let hwnd = CreateWindowExW(
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
		);

		if hwnd.is_null() {
			eprintln!("Failed to create window");
			UnregisterClassW(class_name.as_ptr(), GetModuleHandleW(null_mut()));
			return;
		}

		println!("Window created with HWND: {:?}", hwnd);

		let mut msg = std::mem::zeroed();
		while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
			if msg.message == 0x401 {
				break;
			}
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}

		DestroyWindow(hwnd);
		UnregisterClassW(class_name.as_ptr(), GetModuleHandleW(null_mut()));

		let mut wcex: WNDCLASSEXW = std::mem::zeroed();
		wcex.cbSize = size_of::<WNDCLASSEXW>() as u32;

		EnumWindows(Some(enum_window_proc), class_name.as_ptr() as LPARAM);

		if GetClassInfoExW(GetModuleHandleW(null_mut()), class_name.as_ptr(), &mut wcex) != 0 {
			UnregisterClassW(class_name.as_ptr(), GetModuleHandleW(null_mut()));
		}
	}
}

unsafe fn send_response_message(recipient: WPARAM, sender: HWND, game_event: S1Event, payload: &[u8]) {
	let op: usize = game_event.into();
	println!("TX Event: {:?} ({:?}), Payload: {:?}", game_event, op, payload);
	let copy_data = COPYDATASTRUCT {
		dwData: op,
		cbData: payload.len() as u32,
		lpData: payload.as_ptr() as *mut _,
	};

	unsafe {
		SendMessageW(recipient as HWND, WM_COPYDATA, sender as WPARAM, &copy_data as *const _ as LPARAM);
	}
}
