extern crate winapi;
extern crate widestring;

use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::mem::transmute;
use std::env::var;
use winapi::shared::lmcons::UNLEN;
use winapi::shared::ntdef::{WCHAR, HANDLE, LPWSTR};
use winapi::um::winbase::{GetUserNameW, LocalFree};
use winapi::um::lmaccess::{NetUserGetInfo, USER_INFO_2};
use winapi::shared::minwindef::{LPBYTE, LPVOID, DWORD};
use winapi::um::lmapibuf::NetApiBufferFree;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::winnt::{TOKEN_QUERY, TOKEN_USER, TOKEN_PRIMARY_GROUP, TokenUser, TokenPrimaryGroup, PSID, TOKEN_INFORMATION_CLASS};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::shared::sddl::ConvertSidToStringSidW;
use winapi::um::errhandlingapi::GetLastError;
use widestring::U16CString;

// For compatibility with libc types on Unix side
#[allow(non_camel_case_types)]
type uid_t = String;
#[allow(non_camel_case_types)]
type gid_t = String;

fn convert_sid_to_string(sid: PSID) -> Option<String> {
    let mut bufptr: LPWSTR = null_mut();
    assert_eq!(
        1, 
        unsafe { 
            ConvertSidToStringSidW(sid, &mut bufptr as *mut _ as *mut LPWSTR)
        }
    );
    let wide_user: U16CString = unsafe {
        U16CString::from_ptr_str(bufptr)
    };
    // TODO: Check for memory leaks
    unsafe {
        LocalFree(bufptr as *const _ as LPVOID)
    };
    wide_user.to_string().ok()
}

fn get_process_token() -> HANDLE {
    let mut h_token: HANDLE = null_mut();
    assert_eq!(
        1,
        unsafe { 
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h_token)
        }
    );
    h_token
}

fn required_bytes(query: TOKEN_INFORMATION_CLASS) -> u32 {
    let mut ret_length: DWORD = 0;
    assert_eq!(
        0, 
        unsafe { 
            GetTokenInformation(
                get_process_token(), 
                query, 
                null_mut(), 
                0,
                &mut ret_length
            )
        }
    );
    assert_eq!(
        122,
        unsafe { GetLastError() }
    );
    ret_length
}

pub fn current_user_id() -> uid_t {
    // Source: https://docs.microsoft.com/en-us/windows/desktop/secauthz/searching-for-a-sid-in-an-access-token-in-c--
    let h_token = get_process_token();
    let sizeof_user_info = required_bytes(TokenUser);
    let mut p_user_info: TOKEN_USER = unsafe { std::mem::zeroed() }; // FIXME: Allocate sizeof_user_info bytes
    let mut ret_length: DWORD = 0;
    assert_eq!(
        1, 
        unsafe { 
            GetTokenInformation(
                h_token, 
                TokenUser, 
                &mut p_user_info as *mut _ as LPVOID, 
                sizeof_user_info,
                &mut ret_length
            )
        }
    );
    // TODO: Handle error
    convert_sid_to_string(p_user_info.User.Sid).unwrap()
}

pub fn current_group_id() -> gid_t {
    let h_token = get_process_token();
    let sizeof_group_info = required_bytes(TokenPrimaryGroup);
    let mut p_group_info: TOKEN_PRIMARY_GROUP = unsafe { std::mem::zeroed() }; // FIXME: Allocate sizeof_group_info bytes
    let mut ret_length: DWORD = 0;
    assert_eq!(
        1, 
        unsafe { 
            GetTokenInformation(
                h_token, 
                TokenPrimaryGroup, 
                &mut p_group_info as *mut _ as LPVOID, 
                sizeof_group_info,
                &mut ret_length
            )
        }
    );
    // TODO: Handle error
    convert_sid_to_string(p_group_info.PrimaryGroup).unwrap()
}

struct Login {
    buf: [WCHAR; (UNLEN + 1) as usize],
    buflen: u32,
}

fn login(_uid: uid_t) -> Option<Login> {
    let mut buf: [WCHAR; (UNLEN + 1) as usize] = [0; (UNLEN + 1) as usize];
    let mut buf_size = UNLEN + 1;
    unsafe {
        GetUserNameW(buf.as_mut_ptr(), &mut buf_size);
    }
    assert!(buf.len() >= buf_size as usize);
    Some(Login{
        buf: buf,
        buflen: buf_size,
    })
}

pub fn login_name(uid: uid_t) -> Option<String> {
    let login = login(uid)?;
    // GetUserNameW sets 2nd argument to number of copied characters
    // including terminating NULL character
    // Source: https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-getusernamew
    let name_len = login.buflen as usize - 1;
    match String::from_utf16(&login.buf[0..name_len]) {
        Ok(name) => Some(name),
        Err(_) => None,
    }
}

// Source: https://docs.microsoft.com/en-us/windows/desktop/netmgmt/looking-up-a-users-full-name
pub fn user_full_name(uid: uid_t) -> Option<String> {
    let login = login(uid)?;
    let mut bufptr: LPBYTE = null_mut();
    let status = unsafe {
        NetUserGetInfo(
            null(),   // Current host
            login.buf.as_ptr(), // Current user
            2,                  // return USER_INFO_2
            &mut bufptr as *mut LPBYTE,
        )     
    };
    assert!(status == 0);
    let user_info_2 = unsafe {
        **transmute::<*const LPBYTE, *const *const USER_INFO_2>(&bufptr)
    };

    let wide_user_full_name: U16CString = unsafe {
        U16CString::from_ptr_str(user_info_2.usri2_full_name)
    };

    // TODO: Check for memory leaks
    unsafe {
        NetApiBufferFree(&mut bufptr as *mut _ as LPVOID);
    }

    match wide_user_full_name.to_string() {
        Ok(user_full_name) => Some(user_full_name),
        Err(_) => None
    }
}

pub fn user_home_directory(_uid: uid_t) -> Option<PathBuf> {
    let home_path = var("HOMEPATH").unwrap();
    let home_drive = var("HOMEDRIVE").unwrap();
    let path_buf: PathBuf = [home_drive, home_path].iter().collect();
    Some(path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_name() {
        assert!(login_name("".to_string()).is_some());
    }

    #[test]
    fn test_user_full_name() {
        assert!(user_full_name("".to_string()).is_some());
    }

    #[test]
    fn test_user_home_directory() {
        assert!(user_home_directory("".to_string()).is_some());
    }

    #[test]
    fn test_user_id() {
        println!("UID: {:?}", current_user_id());
        assert_ne!(current_user_id(), "");
    }

    #[test]
    fn test_group_id() {
        println!("GID: {:?}", current_group_id());
        assert_ne!(current_group_id(), "");
    }
}
