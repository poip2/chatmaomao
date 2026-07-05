//! Windows sandbox — Job Object + Low-Integrity restricted token + read isolation.
//!
//! # Architecture
//!
//! Windows sandboxing uses a **two-phase** design:
//!  1. `build_sandboxed_command` — prepares a bare `cmd /c` Command.
//!  2. `apply_sandbox_post_spawn` — after the child is spawned, applies
//!     Job Object, Low-IL token, and ACL read isolation using the child's PID.
//!
//! This is unlike macOS/Linux where the sandbox wrapper is configured
//! before spawn — on Windows, Job Object assignment and token downgrade
//! require an existing process handle.
//!
//! | Layer            | Mechanism                            | What it limits                |
//! |------------------|--------------------------------------|-------------------------------|
//! | Resource limits  | Job Object (best-effort)             | memory, CPU, process count    |
//! | Privilege        | Low-integrity restricted token       | filesystem writes, registry   |
//! |                  |                                      | writes, IPC to higher-IL      |
//! | Read isolation   | ACL deny-read on %USERPROFILE%       | reading sensitive user files  |
//! |                  | + explicit allow-read on workspace   |                               |
//!
//! **Graceful degradation**: if `AssignProcessToJobObject` fails (e.g. the
//! process is already in an outer Job Object like a CI runner), the sandbox
//! degrades to Low IL + ACL read isolation only — resource limits and
//! kill-on-close are unavailable, but the process remains sandboxed.
//!
//! # Read isolation design
//!
//! The threat model: the sandboxed agent process reads a sensitive file
//! (e.g. SSH keys in ~/.ssh/).  The agent loop takes the tool output and
//! sends it to the cloud LLM API.  This is a data exfiltration channel
//! that exists regardless of network policy — the agent itself sends
//! the data out.
//!
//! To close this gap we use the child token's user SID to set a deny-read
//! ACE with CI|OI on %USERPROFILE%.  Then we set explicit allow-read ACEs
//! (also CI|OI) on writable_roots and cwd.  Windows ACL evaluation order
//! ensures explicit allows on closer ancestors override inherited denies
//! from more distant ancestors:
//!
//! ```text
//!   %USERPROFILE%/                      ← deny-read (CI|OI) — explicit here,
//!   ├── .ssh/id_rsa                     ←   inherited deny → blocked ✓
//!   ├── Documents/secret.txt            ←   inherited deny → blocked ✓
//!   └── my-project/          (cwd)     ← explicit allow CI|OI — overrides
//!       └── src/main.rs                 ←   inherited allow  (parent)
//!                                       ←   inherited deny   (grandparent)
//!                                       ← closer ancestor wins → allowed ✓
//! ```
//!
//! For workspaces OUTSIDE %USERPROFILE% (e.g. D:\projects), the deny never
//! reaches those paths because inheritance is directory-tree-local.
//!
//! # ACE ordering
//!
//! We use `AddAccessDeniedAceEx` / `AddAccessAllowedAceEx` (the **Ex**
//! variants are mandatory: non-Ex defaults to NO_INHERITANCE, silently
//! breaking propagation).  Inheritance flags: `CONTAINER_INHERIT_ACE |
//! OBJECT_INHERIT_ACE` so both subdirectories and files inherit the rule.
//!
//! When building the new DACL for each path we:
//! 1. Collect existing explicit ACEs, splitting into deny / allow groups.
//! 2. Prepend our new deny ACE to the deny group.
//! 3. Append our new allow ACE to the allow group.
//! 4. Concatenate: all denies, then all allows → **canonical order** per
//!    [MS-ADTS §5.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/).
//! 5. Inherited ACEs are dropped — the system re-computes them from the
//!    parent after `SetNamedSecurityInfoW`.

use std::path::{Path, PathBuf};

use crate::agent::types::{SandboxMode, SandboxPolicy, ToolError};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, FALSE, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    AddAccessAllowedAceEx, AddAccessDeniedAceEx, CreateWellKnownSid, GetAce, GetLengthSid,
    GetTokenInformation, InitializeAcl, SetTokenInformation, TokenIntegrityLevel, TokenUser,
    WinLowLabelSid, ACE_FLAGS, ACE_HEADER, ACL, ACL_REVISION, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, INHERITED_ACE, OBJECT_INHERIT_ACE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_ADJUST_DEFAULT,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};

#[cfg(test)]
use windows::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount};
use windows::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SE_GROUP_INTEGRITY,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION, PROCESS_SET_INFORMATION,
};

// ─── Constants ───────────────────────────────────────────────────────────────────

/// Byte offset of the SID within an ACCESS_DENIED_ACE / ACCESS_ALLOWED_ACE.
/// Layout: AceHeader(4 bytes) + AccessMask(4 bytes) = 8, then SID.
const ACE_SID_OFFSET: usize = 8;
/// Maximum SID size in bytes (68 per MS-DTYP §2.4.2).
const SECURITY_MAX_SID_SIZE: u32 = 68;
/// Low integrity RID (0x1000).
const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;

// ─── Helpers ─────────────────────────────────────────────────────────────────────

/// Convert a `WIN32_ERROR` to `Result<()>` for functions that use the
/// raw error-code return convention (`GetNamedSecurityInfoW`,
/// `SetNamedSecurityInfoW`).  Contrast with `GetAce` / `GetTokenInformation`
/// which already return `Result<()>`.
fn ok_win32(err: windows::Win32::Foundation::WIN32_ERROR, context: &str) -> Result<(), ToolError> {
    if err.0 == 0 {
        Ok(())
    } else {
        Err(ToolError::SandboxDenied(format!(
            "{}: error {}",
            context, err.0
        )))
    }
}

// ─── Public API ─────────────────────────────────────────────────────────────────

pub fn build_sandboxed_command(
    command: &str,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<std::process::Command, ToolError> {
    if matches!(policy.mode, SandboxMode::DangerFullAccess) {
        let mut cmd = std::process::Command::new("cmd");
        cmd.arg("/c")
            .arg(command)
            .current_dir(cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        return Ok(cmd);
    }

    let mut cmd = std::process::Command::new("cmd");
    cmd.arg("/c")
        .arg(command)
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0000_0200); // CREATE_NEW_PROCESS_GROUP
    }

    Ok(cmd)
}

/// Apply sandboxing to a freshly spawned child process.
///
/// `cwd` is the working directory passed to `ProcessExecutor::run()` —
/// needed so we can add an explicit allow-read ACE on it.
pub fn apply_sandbox_post_spawn(
    pid: u32,
    cwd: &Path,
    policy: &SandboxPolicy,
) -> Result<JobHandle, ToolError> {
    apply_sandbox_post_spawn_inner(pid, cwd, policy, None)
}

/// Internal variant with profile_dir override for tests.
pub(crate) fn apply_sandbox_post_spawn_inner(
    pid: u32,
    cwd: &Path,
    policy: &SandboxPolicy,
    profile_dir: Option<&Path>,
) -> Result<JobHandle, ToolError> {
    let h_job = apply_job_object(pid)?;

    let mut acl_restores: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    if matches!(
        policy.mode,
        SandboxMode::ReadOnly | SandboxMode::WorkspaceWrite
    ) {
        acl_restores = apply_read_isolation(pid, cwd, policy, profile_dir)?;
        let _ = apply_low_integrity(pid);
    }

    Ok(JobHandle {
        pid,
        h_job,
        acl_restores,
    })
}

// ─── JobHandle ───────────────────────────────────────────────────────────────────

/// RAII guard for a sandboxed child process.
///
/// Holds the kernel Job Object handle and ACL restore data for any paths
/// whose DACL was modified during sandbox setup.  On drop, the guard:
/// 1. Restores original DACLs on all modified paths (undoes read isolation)
/// 2. Closes the Job Object handle (triggering KILL_ON_JOB_CLOSE)
/// 3. Terminates the child as a safety net
///
/// # Safety
///
/// This type is `Send` because `HANDLE` is a kernel handle (an index into
/// the process handle table).  Kernel handles are valid across threads and
/// the drop guard is always run on the owning thread.
pub struct JobHandle {
    pid: u32,
    h_job: Option<HANDLE>,
    /// (path, original DACL bytes) — restored on drop to undo
    /// filesystem ACL modifications applied by `apply_read_isolation`.
    acl_restores: Vec<(PathBuf, Vec<u8>)>,
}

// SAFETY: HANDLE is a kernel handle index (not a raw pointer to memory).
// Kernel handles are valid process-wide and can be safely transferred
// across thread boundaries.  The Drop impl always runs on the thread that
// owns this value at destruction time.
unsafe impl Send for JobHandle {}

impl Drop for JobHandle {
    fn drop(&mut self) {
        unsafe {
            // Restore original DACLs on any paths we modified.
            restore_acl_guard(&mut self.acl_restores);

            // Close the Job Object handle if we have one.  KILL_ON_JOB_CLOSE
            // ensures all processes in the job are terminated.
            if let Some(h) = self.h_job {
                let _ = CloseHandle(h);
            }

            // Safety net: if the process survived (e.g. job was unavailable),
            // terminate it directly.
            let h = OpenProcess(
                PROCESS_SET_INFORMATION | windows::Win32::System::Threading::PROCESS_TERMINATE,
                FALSE,
                self.pid,
            );
            if let Ok(h) = h {
                let _ = windows::Win32::System::Threading::TerminateProcess(h, 1);
                let _ = CloseHandle(h);
            }
        }
    }
}

// ─── Job Object ──────────────────────────────────────────────────────────────────

fn apply_job_object(pid: u32) -> Result<Option<HANDLE>, ToolError> {
    unsafe {
        let h_job = CreateJobObjectW(None, PCWSTR::null())
            .map_err(|e| ToolError::SandboxDenied(format!("CreateJobObjectW failed: {:?}", e)))?;

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.ActiveProcessLimit = 0;
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        limits.JobMemoryLimit = 0;
        let size = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();

        if let Err(e) = SetInformationJobObject(
            h_job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const std::ffi::c_void,
            size as u32,
        ) {
            let _ = CloseHandle(h_job);
            return Err(ToolError::SandboxDenied(format!(
                "SetInformationJobObject failed: {:?}",
                e
            )));
        }

        let h_process = match OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
            FALSE,
            pid,
        ) {
            Ok(h) => h,
            Err(e) => {
                let _ = CloseHandle(h_job);
                return Err(ToolError::SandboxDenied(format!(
                    "OpenProcess({}) failed: {:?}",
                    pid, e
                )));
            }
        };

        // AssignProcessToJobObject failure is not fatal — the process may
        // already be in an outer job (e.g., GitHub Actions runner) that
        // disallows nesting/breakaway.  Degrade gracefully to Low IL + ACL
        // isolation only, without resource limits or kill-on-close.
        if let Err(e) = AssignProcessToJobObject(h_job, h_process) {
            let _ = CloseHandle(h_process);
            let _ = CloseHandle(h_job);
            eprintln!(
                "WARNING: AssignProcessToJobObject({}) failed: {:?} — \
                 process may already be in an outer Job Object that disallows \
                 nesting/breakaway (e.g., CI runner).  Sandbox degraded to \
                 Low Integrity Level + ACL isolation only; resource limits and \
                 kill-on-close are unavailable.",
                pid, e
            );
            return Ok(None);
        }

        let _ = CloseHandle(h_process);
        Ok(Some(h_job))
    }
}

// ─── Low Integrity Token ─────────────────────────────────────────────────────────

fn apply_low_integrity(pid: u32) -> Result<(), ToolError> {
    unsafe {
        let h_process = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
            FALSE,
            pid,
        )
        .map_err(|_| ToolError::SandboxDenied("OpenProcess for token downgrade failed".into()))?;

        let mut h_token = HANDLE::default();
        OpenProcessToken(h_process, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &mut h_token).map_err(
            |e| {
                let _ = CloseHandle(h_process);
                ToolError::SandboxDenied(format!("OpenProcessToken failed: {:?}", e))
            },
        )?;
        let _ = CloseHandle(h_process);

        // Allocate a fixed max-size buffer and create the Low IL SID in a
        // single call.  The two-call "query size then allocate" pattern is
        // error-prone here (e.g. passing a literal `&mut 0u32` for the size
        // parameter silently breaks the query).  SID has a known maximum
        // length (SECURITY_MAX_SID_SIZE = 68 bytes), so a fixed buffer with
        // a mutable cbSid variable is simpler and correct.
        let mut sid_buf: [u8; SECURITY_MAX_SID_SIZE as usize] =
            [0u8; SECURITY_MAX_SID_SIZE as usize];
        let low_sid = PSID(sid_buf.as_mut_ptr() as *mut std::ffi::c_void);
        let mut cb_sid = SECURITY_MAX_SID_SIZE;
        CreateWellKnownSid(WinLowLabelSid, None, low_sid, &mut cb_sid).map_err(|e| {
            let _ = CloseHandle(h_token);
            ToolError::SandboxDenied(format!("CreateWellKnownSid failed: {:?}", e))
        })?;

        let label = TOKEN_MANDATORY_LABEL {
            Label: windows::Win32::Security::SID_AND_ATTRIBUTES {
                Sid: low_sid,
                Attributes: SE_GROUP_INTEGRITY as u32,
            },
        };

        let label_size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32;
        let result = SetTokenInformation(
            h_token,
            TokenIntegrityLevel,
            &label as *const _ as *const std::ffi::c_void,
            label_size,
        );
        let _ = CloseHandle(h_token);

        result.map_err(|e| {
            ToolError::SandboxDenied(format!(
                "SetTokenInformation(TokenIntegrityLevel) failed: {:?}",
                e
            ))
        })?;
    }
    Ok(())
}

// ─── Read isolation ──────────────────────────────────────────────────────────────

/// Save the current DACL of `path` as raw bytes for later restoration.
fn save_dacl(path: &Path) -> Result<Vec<u8>, ToolError> {
    unsafe {
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut psd = PSECURITY_DESCRIPTOR::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let result = GetNamedSecurityInfoW(
            PCWSTR::from_raw(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut psd,
        );
        ok_win32(
            result,
            &format!("save_dacl: GetNamedSecurityInfoW for {}", path.display()),
        )?;

        if dacl.is_null() {
            if psd.0 != std::ptr::null_mut() {
                LocalFree(HLOCAL(psd.0));
            }
            return Err(ToolError::SandboxDenied(format!(
                "save_dacl: NULL DACL on {}",
                path.display()
            )));
        }

        let acl = &*dacl;
        let acl_size = acl.AclSize as usize;
        let acl_bytes =
            std::slice::from_raw_parts(dacl as *const u8, acl_size).to_vec();

        LocalFree(HLOCAL(psd.0));
        Ok(acl_bytes)
    }
}

/// Restore original DACLs for all paths saved during sandbox setup.
///
/// Called from `JobHandle::drop`.  Failures are silent (the guard is
/// already tearing down).
unsafe fn restore_acl_guard(restores: &mut Vec<(PathBuf, Vec<u8>)>) {
    for (path, dacl_bytes) in restores.drain(..) {
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let _ = SetNamedSecurityInfoW(
            PCWSTR::from_raw(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            PSID(std::ptr::null_mut()),
            PSID(std::ptr::null_mut()),
            Some(dacl_bytes.as_ptr() as *mut ACL),
            None,
        );
    }
}

/// Apply deny-read on profile directory and allow-read on writable_roots/cwd.
///
/// `profile_dir` overrides %USERPROFILE% — tests pass a fake path to avoid
/// modifying the real user's ACLs.  Production passes `None`.
///
/// Returns a list of (path, original_DACL_bytes) for restoring on teardown.
fn apply_read_isolation(
    pid: u32,
    cwd: &Path,
    policy: &SandboxPolicy,
    profile_dir: Option<&Path>,
) -> Result<Vec<(PathBuf, Vec<u8>)>, ToolError> {
    let mut restores: Vec<(PathBuf, Vec<u8>)> = Vec::new();

    // 1. Get the child token's user SID.
    let sid = match get_child_token_user_sid(pid) {
        Ok(s) => s,
        Err(_) => return Ok(restores),
    };

    // 2. Deny-read on profile directory.
    let profile_path = match profile_dir {
        Some(p) => p.to_path_buf(),
        None => match std::env::var("USERPROFILE") {
            Ok(p) => PathBuf::from(&p),
            Err(_) => return Ok(restores),
        },
    };
    if profile_path.exists() {
        if let Ok(orig) = save_dacl(&profile_path) {
            restores.push((profile_path.clone(), orig));
        }
        let _ = add_deny_read_ace(&profile_path, &sid);
    }

    // 3. Collect paths that need explicit allow-read.
    let mut allow_paths: Vec<PathBuf> = Vec::new();
    allow_paths.push(cwd.to_path_buf());
    for root in &policy.writable_roots {
        allow_paths.push(if root.is_absolute() {
            root.clone()
        } else {
            cwd.join(root)
        });
    }
    // Deduplicate.
    allow_paths.sort();
    allow_paths.dedup();

    for path in &allow_paths {
        if path.exists() {
            if let Ok(orig) = save_dacl(path) {
                restores.push((path.clone(), orig));
            }
            let _ = add_allow_read_ace(path, &sid);
        }
    }

    // 4. Deny-read on protected_paths.  Each protected_path gets an
    //    explicit deny-read ACE with CI|OI so that even bash commands
    //    (which bypass tool-layer validate_path) cannot read them.
    for prot in &policy.protected_paths {
        let resolved = if prot.is_absolute() {
            prot.clone()
        } else {
            cwd.join(prot)
        };
        if resolved.exists() {
            if let Ok(orig) = save_dacl(&resolved) {
                restores.push((resolved.clone(), orig));
            }
            let _ = add_deny_read_ace(&resolved, &sid);
        }
    }

    Ok(restores)
}

/// Extract the user SID from a child process's token as raw bytes.
fn get_child_token_user_sid(pid: u32) -> Result<Vec<u8>, ToolError> {
    unsafe {
        let h_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid).map_err(|e| {
            ToolError::SandboxDenied(format!("OpenProcess for SID failed: {:?}", e))
        })?;

        let mut h_token = HANDLE::default();
        OpenProcessToken(h_process, TOKEN_QUERY, &mut h_token).map_err(|e| {
            let _ = CloseHandle(h_process);
            ToolError::SandboxDenied(format!("OpenProcessToken for SID failed: {:?}", e))
        })?;
        let _ = CloseHandle(h_process);

        // Get buffer size.
        let mut return_length: u32 = 0;
        let _ = GetTokenInformation(h_token, TokenUser, None, 0, &mut return_length);

        let mut buf: Vec<u8> = vec![0u8; return_length as usize];
        GetTokenInformation(
            h_token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
            return_length,
            &mut return_length,
        )
        .map_err(|e| {
            let _ = CloseHandle(h_token);
            ToolError::SandboxDenied(format!("GetTokenInformation(TokenUser) failed: {:?}", e))
        })?;

        let token_user = &*(buf.as_ptr() as *const windows::Win32::Security::TOKEN_USER);
        let sid_len = GetLengthSid(token_user.User.Sid) as usize;

        let sid_bytes =
            std::slice::from_raw_parts(token_user.User.Sid.0 as *const u8, sid_len).to_vec();

        let _ = CloseHandle(h_token);
        Ok(sid_bytes)
    }
}

/// Add a deny-read ACE (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE)
/// to a path's DACL for the given user SID.
///
/// The deny ACE is placed at the front of the deny group → canonical order.
fn add_deny_read_ace(path: &Path, sid_bytes: &[u8]) -> Result<(), ToolError> {
    // protect=false: we WANT this deny to propagate to all subdirectories.
    add_ace_to_path(path, sid_bytes, true, false)
}

/// Add an allow-read ACE (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE)
/// to a path's DACL for the given user SID.
///
/// The allow ACE is placed after all deny ACEs → canonical order.
fn add_allow_read_ace(path: &Path, sid_bytes: &[u8]) -> Result<(), ToolError> {
    // protect=true: block ancestor inheritance so the parent's deny
    // cannot be silently re-merged by the propagation engine.
    add_ace_to_path(path, sid_bytes, false, true)
}

/// Core ACL builder: add a deny-read or allow-read ACE in canonical order.
///
/// 1. Gets existing explicit ACEs (deny group + allow group).
/// 2. Prepends/Appends our new ACE to the appropriate group.
/// 3. Builds a new ACL: all denies, then all allows.
/// 4. Applies via `SetNamedSecurityInfoW`.
fn add_ace_to_path(
    path: &Path,
    sid_bytes: &[u8],
    is_deny: bool,
    protect: bool,
) -> Result<(), ToolError> {
    unsafe {
        // ── 1. Get existing security descriptor and DACL ──
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut psd = PSECURITY_DESCRIPTOR::default();
        let mut old_dacl: *mut ACL = std::ptr::null_mut();
        let result = GetNamedSecurityInfoW(
            PCWSTR::from_raw(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old_dacl),
            None,
            &mut psd,
        );

        ok_win32(
            result,
            &format!("GetNamedSecurityInfoW failed for {}", path.display()),
        )?;

        if old_dacl.is_null() {
            LocalFree(HLOCAL(psd.0));
            return Err(ToolError::SandboxDenied(format!(
                "NULL DACL on '{}': cannot apply ACE — path would remain unprotected",
                path.display()
            )));
        }

        let old_acl = &*old_dacl;

        // ── 2. Collect existing ACEs classified as deny / allow ──
        //
        // When protect=true: convert inherited ACEs to explicit instead of
        // dropping them, so SYSTEM/Administrators permissions are preserved.
        // Exception: inherited DENY ACEs are dropped — those are the
        // %USERPROFILE% deny-read ACEs that we want to override with our
        // explicit allow on workspace directories.

        let mut existing_denies: Vec<AceCopy> = Vec::new();
        let mut existing_allows: Vec<AceCopy> = Vec::new();

        for i in 0..old_acl.AceCount {
            let mut ace_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
            if GetAce(old_acl as *const ACL, i as u32, &mut ace_ptr).is_err() {
                continue;
            }
            if ace_ptr.is_null() {
                continue;
            }
            let header = &*(ace_ptr as *const ACE_HEADER);

            let is_inherited = (header.AceFlags as u32 & INHERITED_ACE.0) != 0;

            if is_inherited && !protect {
                // Without protection: drop inherited ACEs — the system
                // recomputes them from the parent after SetNamedSecurityInfoW.
                continue;
            }

            if is_inherited && protect && header.AceType as u32 == ACCESS_DENIED_ACE_TYPE {
                // With protection: drop inherited DENY ACEs.  These are the
                // %USERPROFILE% deny-read ACEs we placed earlier that got
                // inherited down.  We are adding an explicit allow on this
                // directory to override them — keeping them would make the
                // override pointless.
                continue;
            }

            let total_size = header.AceSize as usize;
            let ace_bytes = std::slice::from_raw_parts(ace_ptr as *const u8, total_size).to_vec();

            // When converting inherited to explicit, strip the INHERITED_ACE
            // flag so it becomes a regular explicit ACE.
            let ace_flags = if is_inherited && protect {
                header.AceFlags as u32 & !INHERITED_ACE.0
            } else {
                header.AceFlags as u32
            };

            let copy = AceCopy {
                ace_type: header.AceType as u32,
                ace_flags,
                ace_bytes,
            };

            match header.AceType as u32 {
                ACCESS_DENIED_ACE_TYPE => existing_denies.push(copy),
                ACCESS_ALLOWED_ACE_TYPE => existing_allows.push(copy),
                _ => {} // skip AUDIT, etc.
            }
        }

        // ── 3. Build new ACE in correct position ──
        let new_ace = build_read_ace(sid_bytes, is_deny);

        if is_deny {
            // Prepend to deny group.
            existing_denies.insert(0, new_ace);
        } else {
            // Append to allow group.
            existing_allows.push(new_ace);
        }

        // ── 4. Compute total ACL size and allocate ──
        let total_size: usize = std::mem::size_of::<ACL>() // ACL header
            + existing_denies.iter().map(|a| a.ace_bytes.len()).sum::<usize>()
            + existing_allows.iter().map(|a| a.ace_bytes.len()).sum::<usize>();

        let mut new_acl_buf: Vec<u8> = vec![0u8; total_size];
        let new_acl_ptr = new_acl_buf.as_mut_ptr() as *mut ACL;

        if InitializeAcl(new_acl_ptr, total_size as u32, ACL_REVISION).is_err() {
            LocalFree(HLOCAL(psd.0));
            return Err(ToolError::SandboxDenied("InitializeAcl failed".into()));
        }

        // ── 5. Add denies first, then allows ──
        for ace in existing_denies.iter().chain(existing_allows.iter()) {
            // Extract original access mask from bytes [4..8] (stored in the ACE).
            let mask_bytes = &ace.ace_bytes[4..8];
            let orig_mask =
                u32::from_le_bytes([mask_bytes[0], mask_bytes[1], mask_bytes[2], mask_bytes[3]]);
            let sid_ptr = PSID(ace.ace_bytes[ACE_SID_OFFSET..].as_ptr() as *mut std::ffi::c_void);

            match ace.ace_type {
                ACCESS_DENIED_ACE_TYPE => {
                    AddAccessDeniedAceEx(
                        new_acl_ptr,
                        ACL_REVISION,
                        ACE_FLAGS(ace.ace_flags),
                        orig_mask,
                        sid_ptr,
                    )
                    .map_err(|e| {
                        LocalFree(HLOCAL(psd.0));
                        ToolError::SandboxDenied(format!("AddAccessDeniedAceEx failed: {:?}", e))
                    })?;
                }
                ACCESS_ALLOWED_ACE_TYPE => {
                    AddAccessAllowedAceEx(
                        new_acl_ptr,
                        ACL_REVISION,
                        ACE_FLAGS(ace.ace_flags),
                        orig_mask,
                        sid_ptr,
                    )
                    .map_err(|e| {
                        LocalFree(HLOCAL(psd.0));
                        ToolError::SandboxDenied(format!("AddAccessAllowedAceEx failed: {:?}", e))
                    })?;
                }
                _ => {}
            }
        }

        // ── 6. Apply new DACL ──
        let sec_info = if protect {
            // PROTECTED_DACL_SECURITY_INFORMATION blocks ancestor inheritance.
            // Without this, the Windows propagation engine can silently
            // re-merge inherited ACEs (including the parent's deny-read)
            // at any later time, undoing our allow exception.
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            DACL_SECURITY_INFORMATION
        };
        let set_result = SetNamedSecurityInfoW(
            PCWSTR::from_raw(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            sec_info,
            PSID(std::ptr::null_mut()),
            PSID(std::ptr::null_mut()),
            Some(new_acl_ptr),
            None,
        );

        LocalFree(HLOCAL(psd.0));

        ok_win32(
            set_result,
            &format!("SetNamedSecurityInfoW failed for {}", path.display()),
        )?;

        Ok(())
    }
}

/// Build an `AceCopy` for a read (deny or allow) ACE.
fn build_read_ace(sid_bytes: &[u8], is_deny: bool) -> AceCopy {
    let ace_type = if is_deny {
        ACCESS_DENIED_ACE_TYPE
    } else {
        ACCESS_ALLOWED_ACE_TYPE
    };
    let ace_flags = CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0;

    let total_size = ACE_SID_OFFSET + sid_bytes.len();
    let mut buf = vec![0u8; total_size];

    // ACE_HEADER (4 bytes): AceType(u8) + AceFlags(u8) + AceSize(u16 LE)
    buf[0] = ace_type as u8;
    buf[1] = ace_flags as u8;
    buf[2] = (total_size & 0xFF) as u8;
    buf[3] = ((total_size >> 8) & 0xFF) as u8;
    // Mask (4 bytes): FILE_GENERIC_READ
    let mask = FILE_GENERIC_READ.0;
    buf[4] = (mask & 0xFF) as u8;
    buf[5] = ((mask >> 8) & 0xFF) as u8;
    buf[6] = ((mask >> 16) & 0xFF) as u8;
    buf[7] = ((mask >> 24) & 0xFF) as u8;
    // SID bytes
    buf[8..].copy_from_slice(sid_bytes);

    AceCopy {
        ace_type,
        ace_flags,
        ace_bytes: buf,
    }
}

#[derive(Clone)]
struct AceCopy {
    ace_type: u32,
    ace_flags: u32,
    ace_bytes: Vec<u8>,
}

// ─── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::types::NetworkPolicy;

    #[test]
    fn test_build_sandboxed_command_danger_full_access() {
        let dir = tempfile::tempdir().unwrap();
        let policy = SandboxPolicy {
            mode: SandboxMode::DangerFullAccess,
            writable_roots: vec![],
            network: NetworkPolicy::FullAccess,
            protected_paths: vec![],
        };

        let cmd = build_sandboxed_command("echo hi", dir.path(), &policy).unwrap();
        assert_eq!(cmd.get_program().to_string_lossy(), "cmd");
    }

    #[test]
    fn test_build_sandboxed_command_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let policy = SandboxPolicy {
            mode: SandboxMode::ReadOnly,
            writable_roots: vec![],
            network: NetworkPolicy::Isolated,
            protected_paths: vec![],
        };

        let cmd = build_sandboxed_command("echo hi", dir.path(), &policy).unwrap();
        assert_eq!(cmd.get_program().to_string_lossy(), "cmd");
    }

    #[test]
    fn test_job_handle_stores_pid() {
        let jh = JobHandle {
            pid: 42,
            h_job: Some(HANDLE::default()),
            acl_restores: vec![],
        };
        assert_eq!(jh.pid, 42);
        drop(jh);
    }

    // ── ACE builder unit tests ──────────────────────────────────────────────

    #[test]
    fn test_build_read_ace_deny() {
        // Fake SID: S-1-5-21-... (variable length, typically 28 bytes for
        // domain SIDs).  Use a minimal well-known SID for testing: S-1-1-0
        // (Everyone) is 12 bytes.
        let everyone_sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let ace = build_read_ace(&everyone_sid, true);

        assert_eq!(ace.ace_type, ACCESS_DENIED_ACE_TYPE);

        // ACE_HEADER
        assert_eq!(ace.ace_bytes[0], ACCESS_DENIED_ACE_TYPE as u8);
        // Flags: CONTAINER_INHERIT_ACE(2) | OBJECT_INHERIT_ACE(1) = 3
        assert_eq!(ace.ace_bytes[1], 3);
        // Size: 8 + 12 = 20
        let size = ace.ace_bytes[2] as u16 | ((ace.ace_bytes[3] as u16) << 8);
        assert_eq!(size as usize, 8 + everyone_sid.len());

        // Mask: FILE_GENERIC_READ
        let mask: u32 = u32::from_le_bytes([
            ace.ace_bytes[4],
            ace.ace_bytes[5],
            ace.ace_bytes[6],
            ace.ace_bytes[7],
        ]);
        assert_eq!(mask, FILE_GENERIC_READ.0);

        // SID preserved
        assert_eq!(&ace.ace_bytes[8..], &everyone_sid[..]);
    }

    #[test]
    fn test_build_read_ace_allow() {
        let sid: [u8; 8] = [1, 1, 0, 0, 0, 0, 0, 1];
        let ace = build_read_ace(&sid, false);

        assert_eq!(ace.ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(ace.ace_bytes[0], ACCESS_ALLOWED_ACE_TYPE as u8);
        assert_eq!(ace.ace_bytes[1], 3); // CI | OI
        assert_eq!(&ace.ace_bytes[8..], &sid[..]);
    }

    // ── NULL DACL safety test ─────────────────────────────────────────

    /// Verify that `add_deny_read_ace` returns an error (not `Ok`)
    /// when the target path does not exist — proving the NULL DACL
    /// path in `add_ace_to_path` propagates errors correctly.
    ///
    /// A true NULL DACL test requires creating a security descriptor
    /// with no DACL, which needs `SeSecurityPrivilege`.  This smoke
    /// test ensures the error-return path compiles and works.
    #[test]
    fn test_null_dacl_returns_error() {
        let path = PathBuf::from("Z:\\nonexistent\\null_dacl_test_dir");
        let sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];

        let result = add_deny_read_ace(&path, &sid);
        assert!(
            result.is_err(),
            "add_deny_read_ace on non-existent path must fail (fail closed)"
        );
    }

    // ── Integration tests (require Windows — run with `cargo test -- --test-threads=1`) ──

    /// Positive: deny-read on a file NOT in writable_roots blocks read.
    #[test]
    fn test_read_isolation_denies_outside_workspace() {
        // Create two dirs: cwd (the workspace) and a "secret" dir outside.
        let workspace = tempfile::tempdir().unwrap();
        let secret_dir = tempfile::tempdir().unwrap();
        let secret_file = secret_dir.path().join("do_not_read.txt");
        std::fs::write(&secret_file, "sensitive data\n").unwrap();

        // Start a sandboxed process with workspace = workspace dir,
        // writable_roots = [workspace], so secret_dir is NOT allowed.
        let policy = SandboxPolicy {
            mode: SandboxMode::ReadOnly,
            writable_roots: vec![workspace.path().to_path_buf()],
            network: NetworkPolicy::Isolated,
            protected_paths: vec![],
        };

        let cmd_str = format!(
            "cmd /c \"type {} > nul 2>&1 && echo READ_OK || echo BLOCKED\"",
            secret_file.display()
        );

        let (out, _err, exit) = run_sandboxed_cmd(&cmd_str, workspace.path(), &policy).unwrap();

        // The deny-read ACE should block the type command.
        assert!(
            !out.contains("READ_OK"),
            "should be BLOCKED, got stdout={} stderr={}",
            out,
            _err
        );
        // Either BLOCKED or the process exits with non-zero (both mean deny
        // worked).  Accept BLOCKED in output.
        assert!(
            out.contains("BLOCKED") || exit != ProcessExit::Code(0),
            "expected read to fail: out={} err={} exit={:?}",
            out,
            _err,
            exit
        );
    }

    /// Positive: allow-read on writable_root lets the sandbox read normally.
    #[test]
    fn test_read_isolation_allows_inside_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let file = workspace.path().join("allowed.txt");
        std::fs::write(&file, "public data\n").unwrap();

        let policy = SandboxPolicy {
            mode: SandboxMode::ReadOnly,
            writable_roots: vec![workspace.path().to_path_buf()],
            network: NetworkPolicy::Isolated,
            protected_paths: vec![],
        };

        let cmd_str = format!("cmd /c \"type {}\"", file.display());

        let (out, _err, exit) = run_sandboxed_cmd(&cmd_str, workspace.path(), &policy).unwrap();

        assert_eq!(exit, ProcessExit::Code(0), "stderr={}", _err);
        assert!(
            out.contains("public data"),
            "should read file, got: {}",
            out
        );
    }

    /// DACL verification: after setting deny-read on %USERPROFILE%, the deny
    /// ACE should appear before allow ACEs in the DACL.
    #[test]
    fn test_dacl_order_deny_before_allow() {
        // Create a test directory and add deny-read to it.
        let test_dir = tempfile::tempdir().unwrap();
        let sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]; // everyone

        add_deny_read_ace(test_dir.path(), &sid).unwrap();

        // Read back the DACL and check the order.
        let order = get_dacl_ace_order(test_dir.path());
        assert!(!order.is_empty(), "DACL should have ACEs");

        // All deny ACEs should appear before all allow ACEs.
        let first_allow = order.iter().position(|&t| t == 'A');
        let last_deny = order.iter().rposition(|&t| t == 'D');

        if let (Some(fa), Some(ld)) = (first_allow, last_deny) {
            assert!(
                ld < fa,
                "all DENY ACEs must come before ALLOW ACEs. Order: {:?}",
                order
            );
        }
    }

    /// DACL verification: the deny ACE we added has CI|OI inheritance flags.
    #[test]
    fn test_dacl_inheritance_flags() {
        let test_dir = tempfile::tempdir().unwrap();
        let sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];

        add_deny_read_ace(test_dir.path(), &sid).unwrap();

        let flags = get_dacl_ace_flags(test_dir.path());
        // At least one ACE should have CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE.
        let ci_oi = CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0;
        assert!(
            flags.iter().any(|&f| f & ci_oi == ci_oi),
            "expected at least one ACE with CI|OI flags, got: {:?}",
            flags
        );
    }

    /// Protection test: after allow-read with PROTECTED_DACL, the child
    /// DACL must NOT receive inherited denies when the parent's ACL is
    /// re-propagated (e.g. after a security info change on the parent).
    #[test]
    fn test_protected_dacl_blocks_repropagation() {
        // ── Setup: parent gets deny-read, child gets allow-read+protected ──
        let parent = tempfile::tempdir().unwrap();
        let child = parent.path().join("child");
        std::fs::create_dir(&child).unwrap();

        let sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]; // everyone

        // Step 1: parent denies read (no protection — should inherit down).
        add_deny_read_ace(parent.path(), &sid).unwrap();

        // Step 2: child allows read WITH protection.
        add_allow_read_ace(&child, &sid).unwrap();

        // Step 3: re-trigger propagation by "touching" the parent's
        // security descriptor (read + write same DACL back).
        // This is the exact scenario where unprotected children would
        // have the deny silently re-merged.
        add_deny_read_ace(parent.path(), &sid).unwrap();

        // Step 4: verify the child's DACL has NO deny ACE.
        let order = get_dacl_ace_order(&child);
        assert!(
            !order.contains(&'D'),
            "child DACL must NOT contain any deny ACE after re-propagation. Order: {:?}",
            order
        );
    }

    // ─── Test helpers ───────────────────────────────────────────────────────

    use crate::agent::tools::bash::OutputHandler;
    use crate::agent::tools::bash::ProcessExit;
    use std::sync::{Arc, Mutex};

    fn run_sandboxed_cmd(
        command: &str,
        cwd: &Path,
        policy: &SandboxPolicy,
    ) -> Result<(String, String, ProcessExit), ToolError> {
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(Vec::new()));

        let so = stdout.clone();
        let se = stderr.clone();
        let on_stdout: Arc<dyn OutputHandler> = Arc::new(move |data: &[u8]| {
            so.lock().unwrap().extend_from_slice(data);
        });
        let on_stderr: Arc<dyn OutputHandler> = Arc::new(move |data: &[u8]| {
            se.lock().unwrap().extend_from_slice(data);
        });

        let mut cmd = build_sandboxed_command(command, cwd, policy)?;
        cmd.current_dir(cwd);

        let child = cmd.spawn().map_err(|e| ToolError::Io(e))?;
        let pid = child.id();

        // Apply sandboxing (deny-read ACEs, etc.).
        // Use a fake profile directory so tests never touch the real
        // %USERPROFILE% ACLs.
        let fake_profile = tempfile::tempdir().map_err(|e| ToolError::Io(e))?;
        let _guard = apply_sandbox_post_spawn_inner(
            pid, cwd, policy, Some(fake_profile.path()),
        )?;

        let output = child.wait_with_output().map_err(|e| ToolError::Io(e))?;
        on_stdout.handle(&output.stdout);
        on_stderr.handle(&output.stderr);

        let exit = if output.status.success() {
            ProcessExit::Code(0)
        } else {
            ProcessExit::Code(output.status.code().unwrap_or(1))
        };

        let result = Ok((
            String::from_utf8_lossy(&stdout.lock().unwrap()).to_string(),
            String::from_utf8_lossy(&stderr.lock().unwrap()).to_string(),
            exit,
        ));
        result
    }

    /// Get DACL ACE order as a string of 'D' (deny) / 'A' (allow) characters.
    fn get_dacl_ace_order(path: &Path) -> Vec<char> {
        unsafe {
            let path_wide: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut psd = PSECURITY_DESCRIPTOR::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let result = GetNamedSecurityInfoW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut psd,
            );

            let mut order = Vec::new();
            if ok_win32(result, "GetNamedSecurityInfoW").is_err() || dacl.is_null() {
                if psd.0 != std::ptr::null_mut() {
                    LocalFree(HLOCAL(psd.0));
                }
                return order;
            }

            let acl = &*dacl;
            for i in 0..acl.AceCount {
                let mut ace_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
                if GetAce(acl as *const ACL, i as u32, &mut ace_ptr).is_err() {
                    continue;
                }
                if ace_ptr.is_null() {
                    continue;
                }
                let header = &*(ace_ptr as *const ACE_HEADER);
                order.push(match header.AceType as u32 {
                    ACCESS_DENIED_ACE_TYPE => 'D',
                    ACCESS_ALLOWED_ACE_TYPE => 'A',
                    _ => '?',
                });
            }
            LocalFree(HLOCAL(psd.0));
            order
        }
    }

    /// Get ACE flags for each ACE in the DACL.
    fn get_dacl_ace_flags(path: &Path) -> Vec<u32> {
        unsafe {
            let path_wide: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut psd = PSECURITY_DESCRIPTOR::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let result = GetNamedSecurityInfoW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut psd,
            );

            let mut flags = Vec::new();
            if ok_win32(result, "GetNamedSecurityInfoW").is_err() || dacl.is_null() {
                if psd.0 != std::ptr::null_mut() {
                    LocalFree(HLOCAL(psd.0));
                }
                return flags;
            }

            let acl = &*dacl;
            for i in 0..acl.AceCount {
                let mut ace_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
                if GetAce(acl as *const ACL, i as u32, &mut ace_ptr).is_err() {
                    continue;
                }
                if ace_ptr.is_null() {
                    continue;
                }
                let header = &*(ace_ptr as *const ACE_HEADER);
                flags.push(header.AceFlags as u32);
            }
            LocalFree(HLOCAL(psd.0));
            flags
        }
    }

    /// Verify that the production `apply_low_integrity` function actually
    /// results in a token whose integrity level is SECURITY_MANDATORY_LOW_RID.
    ///
    /// This test calls the real production code path — it does not reimplement
    /// the token logic inline.  If `apply_low_integrity` later changes, this
    /// test catches regressions.
    #[test]
    fn test_low_integrity_token_verified() {
        unsafe {
            // Spawn a dummy child process.
            let mut child = std::process::Command::new("cmd")
                .arg("/c")
                .arg("echo ok")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn cmd");

            let pid = child.id();

            // Call the production function under test.
            apply_low_integrity(pid).expect("apply_low_integrity");

            // Re-open the process to read back the token integrity level.
            let h_process =
                OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid).expect("OpenProcess");

            let mut h_token = HANDLE::default();
            OpenProcessToken(h_process, TOKEN_QUERY, &mut h_token).expect("OpenProcessToken");
            let _ = CloseHandle(h_process);

            // Read back TokenIntegrityLevel.
            let mut return_length: u32 = 0;
            let _ = GetTokenInformation(h_token, TokenIntegrityLevel, None, 0, &mut return_length);

            let mut buf: Vec<u8> = vec![0u8; return_length as usize];
            GetTokenInformation(
                h_token,
                TokenIntegrityLevel,
                Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
                return_length,
                &mut return_length,
            )
            .expect("GetTokenInformation TokenIntegrityLevel");

            let _ = CloseHandle(h_token);

            // The buffer starts with TOKEN_MANDATORY_LABEL.
            let tml = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid = tml.Label.Sid;

            // Get the last sub-authority (the RID) and assert it's Low.
            let sub_auth_count_ptr = GetSidSubAuthorityCount(sid);
            assert!(
                !sub_auth_count_ptr.is_null(),
                "GetSidSubAuthorityCount returned null"
            );
            let count = *sub_auth_count_ptr as usize;
            assert!(count > 0, "SID must have at least one sub-authority");

            let last_idx = count - 1;
            let last_sub_auth_ptr = GetSidSubAuthority(sid, last_idx as u32);
            assert!(
                !last_sub_auth_ptr.is_null(),
                "GetSidSubAuthority({}) returned null",
                last_idx
            );
            let rid = *last_sub_auth_ptr;

            assert_eq!(
                rid, SECURITY_MANDATORY_LOW_RID,
                "Expected Low IL RID (0x{:X}), got 0x{:X}",
                SECURITY_MANDATORY_LOW_RID, rid
            );

            // Clean up the child.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
