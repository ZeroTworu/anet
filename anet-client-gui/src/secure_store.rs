use std::sync::Mutex;
use std::fs;
use std::path::Path;
use anet_common::encryption::Cipher;
use uuid::Uuid;
use crate::config::AppSettings;

/// 9-байтовая сигнатура зашифрованного файла ANet
pub const MAGIC_ENCRYPTED_HEADER: &[u8; 9] = b"ANET_ENC1";

static IN_MEMORY_URL: Mutex<Option<String>> = Mutex::new(None);
static CACHED_STORAGE_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

pub struct DesktopSecureStore;

impl DesktopSecureStore {
    fn key_file_path() -> std::path::PathBuf {
        AppSettings::data_dir().join(".storage_key")
    }

    fn url_file_path() -> std::path::PathBuf {
        AppSettings::data_dir().join(".server_url")
    }

    pub fn get_or_create_device_storage_key() -> [u8; 32] {
        if let Ok(guard) = CACHED_STORAGE_KEY.lock() {
            if let Some(key) = *guard {
                return key;
            }
        }

        let path = Self::key_file_path();
        if let Ok(bytes) = fs::read(&path) {
            if let Some(decrypted_key) = os_crypto::unprotect_key(&bytes) {
                if decrypted_key.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&decrypted_key);
                    if let Ok(mut guard) = CACHED_STORAGE_KEY.lock() {
                        *guard = Some(key);
                    }
                    return key;
                }
            }
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                if let Some(protected) = os_crypto::protect_key(&key) {
                    let _ = fs::write(&path, protected);
                }
                if let Ok(mut guard) = CACHED_STORAGE_KEY.lock() {
                    *guard = Some(key);
                }
                return key;
            }
        }

        let dir = AppSettings::data_dir();
        let _ = fs::create_dir_all(&dir);
        let mut key = [0u8; 32];
        let u1 = Uuid::new_v4();
        let u2 = Uuid::new_v4();
        key[..16].copy_from_slice(u1.as_bytes());
        key[16..].copy_from_slice(u2.as_bytes());

        if let Some(protected) = os_crypto::protect_key(&key) {
            let _ = fs::write(path, protected);
        } else {
            let _ = fs::write(path, &key);
        }

        if let Ok(mut guard) = CACHED_STORAGE_KEY.lock() {
            *guard = Some(key);
        }
        key
    }

    pub fn encrypt_bytes(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = Self::get_or_create_device_storage_key();
        let cipher = Cipher::new(&key);
        
        let mut nonce = [0u8; 12];
        let rand_uuid = Uuid::new_v4();
        nonce.copy_from_slice(&rand_uuid.as_bytes()[..12]);

        let ciphertext = cipher
            .encrypt(&nonce, bytes::Bytes::copy_from_slice(plaintext))
            .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

        let mut output = Vec::with_capacity(MAGIC_ENCRYPTED_HEADER.len() + 12 + ciphertext.len());
        output.extend_from_slice(MAGIC_ENCRYPTED_HEADER);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub fn decrypt_bytes(raw_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        if raw_data.starts_with(MAGIC_ENCRYPTED_HEADER) {
            let header_len = MAGIC_ENCRYPTED_HEADER.len();
            if raw_data.len() < header_len + 12 + 16 {
                anyhow::bail!("Encrypted file is corrupted or truncated");
            }
            let nonce = &raw_data[header_len..header_len + 12];
            let ciphertext = &raw_data[header_len + 12..];

            let key = Self::get_or_create_device_storage_key();
            let cipher = Cipher::new(&key);
            let decrypted = cipher
                .decrypt(nonce, bytes::Bytes::copy_from_slice(ciphertext))
                .map_err(|e| anyhow::anyhow!("Decryption / MAC check failed: {e}"))?;

            return Ok(decrypted.to_vec());
        }

        Ok(raw_data.to_vec())
    }

    pub fn write_encrypted_string(path: &Path, content: &str) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let encrypted = Self::encrypt_bytes(content.as_bytes())?;
        fs::write(path, encrypted)?;
        Ok(())
    }

    pub fn read_encrypted_string(path: &Path) -> anyhow::Result<String> {
        let bytes = fs::read(path)?;
        let decrypted = Self::decrypt_bytes(&bytes)?;
        let string = String::from_utf8(decrypted)
            .map_err(|e| anyhow::anyhow!("Decrypted content is not valid UTF-8: {e}"))?;
        Ok(string)
    }

    pub fn get_server_config_url() -> Option<String> {
        if let Ok(guard) = IN_MEMORY_URL.lock() {
            if let Some(ref url) = *guard {
                return Some(url.clone());
            }
        }
        let path = Self::url_file_path();
        if let Ok(content) = Self::read_encrypted_string(&path) {
            let trimmed = content.trim().to_string();
            if !trimmed.is_empty() {
                if let Ok(mut guard) = IN_MEMORY_URL.lock() {
                    *guard = Some(trimmed.clone());
                }
                return Some(trimmed);
            }
        }
        None
    }

    pub fn set_server_config_url(url: &str) -> anyhow::Result<()> {
        Self::write_encrypted_string(&Self::url_file_path(), url.trim())?;
        if let Ok(mut guard) = IN_MEMORY_URL.lock() {
            *guard = Some(url.trim().to_string());
        }
        Ok(())
    }

    pub fn delete_server_config_url() -> anyhow::Result<()> {
        let path = Self::url_file_path();
        if path.exists() {
            let _ = fs::remove_file(path);
        }
        if let Ok(mut guard) = IN_MEMORY_URL.lock() {
            *guard = None;
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod os_crypto {
    use std::ptr;

    #[repr(C)]
    struct DATA_BLOB {
        cbData: u32,
        pbData: *mut u8,
    }

    #[link(name = "crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(
            pDataIn: *const DATA_BLOB,
            szDataDescr: *const u16,
            pOptionalEntropy: *const DATA_BLOB,
            pvReserved: *mut std::ffi::c_void,
            pPromptStruct: *mut std::ffi::c_void,
            dwFlags: u32,
            pDataOut: *mut DATA_BLOB,
        ) -> i32;

        fn CryptUnprotectData(
            pDataIn: *const DATA_BLOB,
            ppszDataDescr: *mut *mut u16,
            pOptionalEntropy: *const DATA_BLOB,
            pvReserved: *mut std::ffi::c_void,
            pPromptStruct: *mut std::ffi::c_void,
            dwFlags: u32,
            pDataOut: *mut DATA_BLOB,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    pub fn protect_key(key: &[u8]) -> Option<Vec<u8>> {
        let in_blob = DATA_BLOB {
            cbData: key.len() as u32,
            pbData: key.as_ptr() as *mut u8,
        };
        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        unsafe {
            if CryptProtectData(&in_blob, ptr::null(), ptr::null(), ptr::null_mut(), ptr::null_mut(), 0x01, &mut out_blob) != 0 {
                let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
                LocalFree(out_blob.pbData as *mut _);
                Some(slice)
            } else {
                None
            }
        }
    }

    pub fn unprotect_key(data: &[u8]) -> Option<Vec<u8>> {
        let in_blob = DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        unsafe {
            if CryptUnprotectData(&in_blob, ptr::null_mut(), ptr::null(), ptr::null_mut(), ptr::null_mut(), 0x01, &mut out_blob) != 0 {
                let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
                LocalFree(out_blob.pbData as *mut _);
                Some(slice)
            } else {
                None
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod os_crypto {
    pub fn protect_key(data: &[u8]) -> Option<Vec<u8>> {
        let id = std::fs::read_to_string("/etc/machine-id")
            .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
            .unwrap_or_else(|_| "anet-default-machine-key".to_string());
        let mut out = data.to_vec();
        for (i, b) in out.iter_mut().enumerate() {
            *b ^= id.as_bytes()[i % id.len()];
        }
        Some(out)
    }

    pub fn unprotect_key(data: &[u8]) -> Option<Vec<u8>> {
        protect_key(data)
    }
}
