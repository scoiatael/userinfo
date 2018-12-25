extern crate winapi;

use std::path::PathBuf;
use winapi::shared::lmcons::UNLEN;
use winapi::shared::ntdef::WCHAR;
use winapi::um::winbase::GetUserNameW;

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

pub fn login_name(_uid: uid_t) -> Option<String> {
    let mut buf: [WCHAR; (UNLEN + 1) as usize] = [0; (UNLEN + 1) as usize];
    let mut buf_size = UNLEN + 1;
    unsafe {
        GetUserNameW(buf.as_mut_ptr(), &mut buf_size);
    }
    assert!(buf.len() >= buf_size as usize);
    // GetUserNameW sets 2nd argument to number of copied characters
    // including terminating NULL character
    // Source: https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-getusernamew
    let name_len = buf_size as usize - 1;
    match String::from_utf16(&buf[0..name_len]) {
        Ok(name) => Some(name),
        Err(_) => None,
    }
}

pub fn user_full_name(_uid: uid_t) -> Option<String> {
    Some("foobar".to_owned())
}

pub fn user_home_directory(_uid: uid_t) -> Option<PathBuf> {
    Some(PathBuf::from("c:\\"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id() {
        println!("your name is {:?}", login_name(0));
        assert_eq!(current_user_id(), 12);
    }
}
