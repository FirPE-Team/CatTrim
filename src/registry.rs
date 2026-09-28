#[cfg(not(windows))]
use anyhow::{Result, bail};
#[cfg(not(windows))]
use std::path::Path;
use std::path::PathBuf;

const CBS_LOCATIONS: [&str; 2] = [
    r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages",
    r"Microsoft\Windows\CurrentVersion\Component Based Servicing\PackageIndex",
];

fn invalid_cat_stems(invalid: &[PathBuf]) -> Vec<String> {
    invalid
        .iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("cat"))
        })
        .filter_map(|path| {
            path.file_stem()
                .map(|name| name.to_string_lossy().to_ascii_lowercase())
        })
        .filter(|stem| !stem.is_empty())
        .collect()
}

fn package_matches_invalid_cat(package_name: &str, stems: &[String]) -> bool {
    let package_name = package_name.to_ascii_lowercase();
    stems.iter().any(|stem| package_name.contains(stem))
}

#[cfg(windows)]
mod platform {
    use super::{CBS_LOCATIONS, invalid_cat_stems, package_matches_invalid_cat};
    use anyhow::{Context, Result, anyhow};
    use std::{
        iter::once,
        os::windows::ffi::OsStrExt,
        path::{Path, PathBuf},
        process,
    };
    use windows::{
        Win32::{
            Foundation::{
                CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_NOT_ALL_ASSIGNED, ERROR_PATH_NOT_FOUND,
                GetLastError, HANDLE, LUID, SetLastError, WIN32_ERROR,
            },
            Security::{
                AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_BACKUP_NAME,
                SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
                TOKEN_QUERY,
            },
            System::{
                Registry::{HKEY_LOCAL_MACHINE, RegLoadKeyW, RegUnLoadKeyW},
                Threading::{GetCurrentProcess, OpenProcessToken},
            },
        },
        core::PCWSTR,
    };
    use windows_registry::{Key, LOCAL_MACHINE};
    use windows_result::{Error, HRESULT, WIN32_ERROR as RegistryWin32Error};

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(once(0)).collect()
    }

    fn win_error(operation: &str, code: WIN32_ERROR) -> anyhow::Error {
        anyhow!("{operation} failed with Windows error {}", code.0)
    }

    fn is_not_found(error: &Error) -> bool {
        let file_not_found: HRESULT = RegistryWin32Error(ERROR_FILE_NOT_FOUND.0).into();
        let path_not_found: HRESULT = RegistryWin32Error(ERROR_PATH_NOT_FOUND.0).into();
        error.code() == file_not_found || error.code() == path_not_found
    }

    fn open_key_if_exists(parent: &Key, path: &str) -> Result<Option<Key>> {
        match parent.options().read().write().open(path) {
            Ok(key) => Ok(Some(key)),
            Err(error) if is_not_found(&error) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn enable_privilege(token: HANDLE, name: PCWSTR, display_name: &str) -> Result<()> {
        let mut luid = LUID::default();
        unsafe { LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid) }
            .with_context(|| format!("look up {display_name}"))?;

        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        unsafe {
            SetLastError(WIN32_ERROR(0));
            AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None)
        }
        .with_context(|| format!("enable {display_name}"))?;

        let status = unsafe { GetLastError() };
        if status == ERROR_NOT_ALL_ASSIGNED {
            anyhow::bail!(
                "the process token does not contain {display_name}; run the elevated executable as an administrator"
            );
        }
        if status != WIN32_ERROR(0) {
            return Err(win_error(&format!("enable {display_name}"), status));
        }
        Ok(())
    }

    fn enable_hive_privileges() -> Result<()> {
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        }
        .context("open process token for registry hive privileges")?;
        let token = TokenHandle(token);

        enable_privilege(token.0, SE_BACKUP_NAME, "SeBackupPrivilege")?;
        enable_privilege(token.0, SE_RESTORE_NAME, "SeRestorePrivilege")?;
        Ok(())
    }

    fn delete_key(parent: &Key, name: &str) -> Result<()> {
        let key = parent
            .options()
            .read()
            .write()
            .open(name)
            .with_context(|| format!("open registry key {name}"))?;

        let values = key
            .values()
            .context("enumerate registry values")?
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        for value in values {
            key.remove_value(&value)
                .with_context(|| format!("delete registry value {value:?}"))?;
        }

        let children = key
            .keys()
            .context("enumerate registry subkeys")?
            .collect::<Vec<_>>();
        for child in children {
            delete_key(&key, &child)?;
        }

        drop(key);
        parent
            .remove_tree(name)
            .with_context(|| format!("delete registry key {name}"))
    }

    struct MountedHive {
        name: String,
        loaded: bool,
    }

    impl MountedHive {
        fn load(hive_path: &Path) -> Result<Self> {
            let name = format!("CatTrim_{}", process::id());
            let name_wide = wide(&name);
            let path_wide = hive_path
                .as_os_str()
                .encode_wide()
                .chain(once(0))
                .collect::<Vec<_>>();
            let code = unsafe {
                RegLoadKeyW(
                    HKEY_LOCAL_MACHINE,
                    PCWSTR(name_wide.as_ptr()),
                    PCWSTR(path_wide.as_ptr()),
                )
            };
            if code != WIN32_ERROR(0) {
                return Err(win_error(
                    &format!("mount registry hive {}", hive_path.display()),
                    code,
                ));
            }
            Ok(Self { name, loaded: true })
        }

        fn open(&self) -> Result<Key> {
            LOCAL_MACHINE
                .options()
                .read()
                .write()
                .open(&self.name)
                .context("open mounted registry hive")
        }

        fn unload(mut self) -> Result<()> {
            if self.loaded {
                let name = wide(&self.name);
                let code = unsafe { RegUnLoadKeyW(HKEY_LOCAL_MACHINE, PCWSTR(name.as_ptr())) };
                self.loaded = false;
                if code != WIN32_ERROR(0) {
                    return Err(win_error("unmount registry hive", code));
                }
            }
            Ok(())
        }
    }

    impl Drop for MountedHive {
        fn drop(&mut self) {
            if self.loaded {
                let name = wide(&self.name);
                unsafe {
                    let _ = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, PCWSTR(name.as_ptr()));
                }
            }
        }
    }

    pub fn clean_invalid_cat_entries(image_root: &Path, invalid: &[PathBuf]) -> Result<usize> {
        let stems = invalid_cat_stems(invalid);
        if stems.is_empty() {
            return Ok(0);
        }
        enable_hive_privileges()?;

        let hive_path = image_root
            .join("Windows")
            .join("System32")
            .join("Config")
            .join("SOFTWARE");
        let mounted = MountedHive::load(&hive_path)?;
        let hive = mounted.open()?;
        let mut removed = 0;

        for location in CBS_LOCATIONS {
            let Some(root) = open_key_if_exists(&hive, location)? else {
                continue;
            };
            let children = root
                .keys()
                .with_context(|| format!("enumerate registry key {location}"))?
                .collect::<Vec<_>>();
            for child in children {
                if package_matches_invalid_cat(&child, &stems) {
                    delete_key(&root, &child)
                        .with_context(|| format!(r"remove registry package {location}\{child}"))?;
                    removed += 1;
                }
            }
        }

        drop(hive);
        mounted.unload()?;
        Ok(removed)
    }
}

#[cfg(windows)]
pub use platform::clean_invalid_cat_entries;

#[cfg(not(windows))]
pub fn clean_invalid_cat_entries(_image_root: &Path, _invalid: &[PathBuf]) -> Result<usize> {
    bail!("registry cleanup is only supported on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_package_names_case_insensitively() {
        let stems = vec!["microsoft-windows-example-package~1.0".to_owned()];
        assert!(package_matches_invalid_cat(
            "Microsoft-Windows-Example-Package~1.0~~amd64",
            &stems
        ));
        assert!(!package_matches_invalid_cat("unrelated-package", &stems));
    }
}
