extern crate winapi;
extern crate widestring;

use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::mem::transmute;
use std::env::var;
use winapi::shared::lmcons::UNLEN;
use winapi::shared::ntdef::WCHAR;
use winapi::um::winbase::GetUserNameW;
use winapi::um::lmaccess::{NetUserGetInfo, USER_INFO_2};
use winapi::shared::minwindef::{LPBYTE, LPVOID};
use winapi::um::lmapibuf::NetApiBufferFree;
use widestring::U16CString;

// For compatibility with libc types on Unix side
#[allow(non_camel_case_types)]
type uid_t = u64;
#[allow(non_camel_case_types)]
type gid_t = u64;
    
pub fn current_user_id() -> uid_t {
    12
}

pub fn current_group_id() -> gid_t {
    12
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
    fn test_user_id() {
        println!("your name is {:?}", login_name(0));
        println!("your full name is {:?}", user_full_name(0));
        println!("your home dir is {:?}", user_home_directory(0));
        assert_eq!(current_user_id(), 12);
    }
}
