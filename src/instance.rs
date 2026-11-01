//! Cooperative GUI handoff. No paths, commands, files, network, or process killing.
//!
//! A challenger can cancel before acknowledgment after 120 seconds. Once an idle
//! owner acknowledges, takeover is committed: the challenger waits for its mutex
//! release rather than cancelling an already accepted close. A stuck owner can
//! therefore delay committed handoff. Builds predating this protocol cannot be
//! discovered or safely closed by it.
use anyhow::{Result, anyhow, bail};
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex},
};

pub enum Launch {
    Owner(Instance),
    Forwarded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    None,
    Waiting,
    Close,
}

#[derive(Default)]
struct GateState {
    active: usize,
    closing: bool,
}

impl GateState {
    fn begin(&mut self) -> Result<()> {
        if self.closing {
            bail!("A new copy is taking over; no new work can start");
        }
        self.active = self
            .active
            .checked_add(1)
            .ok_or_else(|| anyhow!("Worker count overflow"))?;
        Ok(())
    }
    fn request(&mut self, live: bool) -> Control {
        if !live {
            self.closing = false;
            return Control::None;
        }
        if self.active != 0 {
            return Control::Waiting;
        }
        self.closing = true;
        Control::Close
    }
}

/// Main-thread-owned instance. Its worker guards may cross thread boundaries.
pub struct Instance {
    state: Arc<Mutex<GateState>>,
    #[cfg(windows)]
    ipc: native::OwnerIpc,
    _thread_bound: PhantomData<Rc<()>>,
}

pub struct WorkGuard {
    state: Arc<Mutex<GateState>>,
}

impl Drop for WorkGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.active = state.active.saturating_sub(1);
        }
    }
}

impl Instance {
    /// Obtain this before spawning a worker, not inside the worker afterwards.
    pub fn begin_work(&self) -> Result<WorkGuard> {
        self.state
            .lock()
            .map_err(|_| anyhow!("Instance work gate is unavailable"))?
            .begin()?;
        Ok(WorkGuard {
            state: self.state.clone(),
        })
    }

    pub fn poll(&self) -> Control {
        let Ok(mut state) = self.state.lock() else {
            return Control::Waiting;
        };
        #[cfg(windows)]
        {
            self.ipc.poll(&mut state).unwrap_or(Control::Waiting)
        }
        #[cfg(not(windows))]
        {
            state.request(false)
        }
    }
}

pub fn coordinate() -> Result<Launch> {
    #[cfg(windows)]
    let ipc = native::coordinate()?;
    Ok(Launch::Owner(Instance {
        state: Arc::new(Mutex::new(GateState::default())),
        #[cfg(windows)]
        ipc,
        _thread_bound: PhantomData,
    }))
}

#[cfg(windows)]
mod native {
    use super::*;
    use anyhow::Context;
    use std::{
        mem::size_of,
        time::{Duration, Instant},
    };
    use windows::{
        Win32::{
            Foundation::{
                CloseHandle, HANDLE, HLOCAL, LocalFree, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
            },
            Security::{
                ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
                Authorization::{
                    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                    GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
                },
                DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl,
                GetTokenInformation, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
                PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
                SYSTEM_MANDATORY_LABEL_ACE, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
                TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenSessionId, TokenUser,
            },
            System::Threading::{
                CreateEventW, CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex,
                ResetEvent, SetEvent, WaitForSingleObject,
            },
        },
        core::{PCWSTR, PWSTR},
    };

    const INFINITE: u32 = u32::MAX;
    const BEFORE_ACK_TIMEOUT: Duration = Duration::from_secs(120);

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    struct MutexLock<'a>(&'a Handle);
    impl<'a> MutexLock<'a> {
        fn acquire(handle: &'a Handle, ms: u32) -> Result<Option<Self>> {
            let result = unsafe { WaitForSingleObject(handle.0, ms) };
            if result == WAIT_OBJECT_0 || result == WAIT_ABANDONED {
                Ok(Some(Self(handle)))
            } else if result == WAIT_TIMEOUT {
                Ok(None)
            } else {
                Err(windows::core::Error::from_thread())
                    .context("Wait for cooperative handoff lock")
            }
        }
    }
    impl Drop for MutexLock<'_> {
        fn drop(&mut self) {
            unsafe {
                let _ = ReleaseMutex(self.0.0);
            }
        }
    }

    fn acquire_owner(handle: &Handle, ms: u32) -> Result<bool> {
        match MutexLock::acquire(handle, ms)? {
            Some(lock) => {
                std::mem::forget(lock);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    // Unlike a borrowed MutexLock, the lifetime owner keeps its own handle.
    struct OwnerLock(Handle);
    impl Drop for OwnerLock {
        fn drop(&mut self) {
            unsafe {
                let _ = ReleaseMutex(self.0.0);
            }
        }
    }

    struct LocalAllocation(HLOCAL);
    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(Some(self.0));
            }
        }
    }

    fn token_data(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>> {
        let mut bytes = 0;
        unsafe {
            let _ = GetTokenInformation(token, class, None, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 64 * 1024 {
            bail!("Windows token metadata is unavailable");
        }
        // The storage must be pointer-aligned for TOKEN_USER/TOKEN_MANDATORY_LABEL.
        let mut data = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(data.as_mut_ptr().cast()),
                bytes,
                &mut bytes,
            )
        }
        .context("Read Windows token metadata")?;
        Ok(data)
    }

    fn sid_text(sid: PSID) -> Result<String> {
        let mut ptr = PWSTR::null();
        unsafe { ConvertSidToStringSidW(sid, &mut ptr) }
            .context("Read Windows security identity")?;
        let _allocation = LocalAllocation(HLOCAL(ptr.0.cast()));
        unsafe { ptr.to_string() }.context("Convert Windows security identity")
    }

    struct Security {
        _descriptor: LocalAllocation,
        attributes: SECURITY_ATTRIBUTES,
        prefix: String,
        user_sid: String,
        integrity_sid: String,
    }

    impl Security {
        fn current(test_scope: Option<&str>) -> Result<Self> {
            let mut token = HANDLE::default();
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
                .context("Read current process identity")?;
            let token = Handle(token);
            let user_data = token_data(token.0, TokenUser)?;
            let user = unsafe { &*user_data.as_ptr().cast::<TOKEN_USER>() };
            let sid = sid_text(user.User.Sid)?;
            let integrity_data = token_data(token.0, TokenIntegrityLevel)?;
            let integrity = unsafe { &*integrity_data.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
            let integrity_sid = sid_text(integrity.Label.Sid)?;
            let session_data = token_data(token.0, TokenSessionId)?;
            let session = unsafe { *session_data.as_ptr().cast::<u32>() };
            // Explicit owner, user-only protected DACL, and mandatory integrity
            // label. Validate existing objects too: a name containing a SID is
            // not authentication against a pre-created spoofed object.
            let sddl: Vec<u16> = format!("O:{sid}D:P(A;;GA;;;{sid})S:(ML;;NW;;;{integrity_sid})")
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(sddl.as_ptr()),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    None,
                )
            }
            .context("Create private handoff security descriptor")?;
            let allocation = LocalAllocation(HLOCAL(descriptor.0));
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: false.into(),
            };
            let mut prefix =
                format!(r"Local\NeonOrchard.AmIGood.Handoff.v1.{sid}.{session}.{integrity_sid}");
            if let Some(scope) = test_scope {
                if scope.is_empty() || !scope.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                {
                    bail!("Invalid private handoff test scope");
                }
                prefix.push_str(".test.");
                prefix.push_str(scope);
            }
            Ok(Self {
                _descriptor: allocation,
                attributes,
                prefix,
                user_sid: sid,
                integrity_sid,
            })
        }
        fn validate(&self, handle: Handle) -> Result<Handle> {
            let mut owner = PSID::default();
            let mut sacl: *mut ACL = std::ptr::null_mut();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            unsafe {
                GetSecurityInfo(
                    handle.0,
                    SE_KERNEL_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | LABEL_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION,
                    Some(&mut owner),
                    None,
                    Some(&mut dacl),
                    Some(&mut sacl),
                    Some(&mut descriptor),
                )
            }
            .ok()
            .context("Verify cooperative handoff object security")?;
            let _allocation = LocalAllocation(HLOCAL(descriptor.0));
            if owner.0.is_null() || sid_text(owner)? != self.user_sid || sacl.is_null() {
                bail!("Cooperative handoff object has an unexpected security owner or label");
            }
            let mut control = 0u16;
            let mut revision = 0u32;
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
                .context("Read handoff DACL control")?;
            if dacl.is_null()
                || control & SE_DACL_PROTECTED.0 == 0
                || unsafe { (*dacl).AceCount } != 1
            {
                bail!(
                    "Cooperative handoff object does not have the required private protected DACL"
                );
            }
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            unsafe { GetAce(dacl, 0, &mut ace) }.context("Read handoff DACL")?;
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            // ACCESS_ALLOWED_ACE_TYPE is 0x00. This protocol has one explicit
            // user allow ACE, with no inheritance, callbacks, or extra trustees.
            if header.AceType != 0 || header.AceFlags != 0 {
                bail!("Cooperative handoff object has an unexpected access ACE");
            }
            let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
            let allowed_sid = PSID(unsafe { (&raw mut (*allowed).SidStart).cast() });
            if sid_text(allowed_sid)? != self.user_sid {
                bail!("Cooperative handoff object grants access to an unexpected principal");
            }
            let mut valid_label = false;
            for index in 0..unsafe { (*sacl).AceCount } as u32 {
                let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
                unsafe { GetAce(sacl, index, &mut ace) }.context("Read handoff integrity label")?;
                // SYSTEM_MANDATORY_LABEL_ACE_TYPE is 0x11 in the Win32 ABI.
                if unsafe { (*ace.cast::<ACE_HEADER>()).AceType } == 0x11 {
                    let label = ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>();
                    let sid = PSID(unsafe { (&raw mut (*label).SidStart).cast() });
                    if sid_text(sid)? != self.integrity_sid || unsafe { (*label).Mask & 1 } == 0 {
                        bail!("Cooperative handoff object integrity does not match this process");
                    }
                    valid_label = true;
                }
            }
            if !valid_label {
                bail!("Cooperative handoff object has no verified mandatory integrity label");
            }
            Ok(handle)
        }
        fn mutex(&self, suffix: &str) -> Result<Handle> {
            let name: Vec<u16> = format!("{}.{}", self.prefix, suffix)
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let handle =
                unsafe { CreateMutexW(Some(&self.attributes), false, PCWSTR(name.as_ptr())) }
                    .map(Handle)
                    .context("Create private cooperative handoff mutex")?;
            self.validate(handle)
        }
        fn event(&self, suffix: &str) -> Result<Handle> {
            let name: Vec<u16> = format!("{}.{}", self.prefix, suffix)
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let handle =
                unsafe { CreateEventW(Some(&self.attributes), true, false, PCWSTR(name.as_ptr())) }
                    .map(Handle)
                    .context("Create private cooperative handoff event")?;
            self.validate(handle)
        }
    }

    #[cfg(test)]
    pub(super) fn test_rejects_world_writable_object() -> Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let scope = format!("{}-{nonce}-spoof", std::process::id());
        let security = Security::current(Some(&scope))?;
        // Same expected owner and integrity, but grants Everyone full access.
        // The extra trustee must be rejected when opening an existing object.
        let sddl: Vec<u16> = format!(
            "O:{}D:P(A;;GA;;;{})(A;;GA;;;WD)S:(ML;;NW;;;{})",
            security.user_sid, security.user_sid, security.integrity_sid,
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .context("Create private test object's forged DACL")?;
        let _allocation = LocalAllocation(HLOCAL(descriptor.0));
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let name: Vec<u16> = format!("{}.Forged", security.prefix)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let forged =
            Handle(unsafe { CreateEventW(Some(&attributes), true, false, PCWSTR(name.as_ptr())) }?);
        // Exercise the normal existing-object opening path, not just a parser.
        let result = security.event("Forged");
        assert!(
            matches!(result, Err(ref error) if error.to_string().contains("private protected DACL"))
        );
        drop(forged);
        Ok(())
    }

    pub(super) struct OwnerIpc {
        // Released last, after other local IPC handles have been closed.
        request: Handle,
        acknowledged: Handle,
        control: Handle,
        challenger: Handle,
        _owner: OwnerLock,
    }

    fn signaled(event: &Handle) -> Result<bool> {
        let result = unsafe { WaitForSingleObject(event.0, 0) };
        if result == WAIT_OBJECT_0 {
            Ok(true)
        } else if result == WAIT_TIMEOUT {
            Ok(false)
        } else {
            Err(windows::core::Error::from_thread()).context("Read cooperative handoff signal")
        }
    }

    impl OwnerIpc {
        pub(super) fn poll(&self, state: &mut GateState) -> Result<Control> {
            // UI poll never blocks waiting for the challenger to release control.
            let Some(_control) = MutexLock::acquire(&self.control, 0)? else {
                return Ok(Control::Waiting);
            };
            if !signaled(&self.request)? {
                return Ok(state.request(false));
            }
            // A dead or cancelled challenger must not close the current copy.
            let live = match MutexLock::acquire(&self.challenger, 0)? {
                Some(_unclaimed) => false,
                None => true,
            };
            if !live {
                unsafe {
                    ResetEvent(self.request.0)?;
                    ResetEvent(self.acknowledged.0)?;
                }
                return Ok(state.request(false));
            }
            let action = state.request(true);
            if action == Control::Close {
                // Local state lock is held by Instance::poll: begin_work cannot
                // race between this zero-worker decision and the closing latch.
                unsafe { SetEvent(self.acknowledged.0) }.context("Acknowledge idle handoff")?;
            }
            Ok(action)
        }
    }

    pub(super) fn coordinate() -> Result<OwnerIpc> {
        coordinate_scoped(None, BEFORE_ACK_TIMEOUT)
    }

    pub(super) fn coordinate_scoped(
        test_scope: Option<&str>,
        timeout: Duration,
    ) -> Result<OwnerIpc> {
        let security = Security::current(test_scope)?;
        let owner = security.mutex("Owner")?;
        let request = security.event("Request")?;
        let acknowledged = security.event("Acknowledged")?;
        let control = security.mutex("Control")?;
        let challenger = security.mutex("Challenger")?;

        // Serialize all contenders, including apparent first owners. Otherwise a
        // third launcher could steal a released owner mutex and clear another
        // challenger's request before that challenger wakes.
        let started = Instant::now();
        let challenger_lock = MutexLock::acquire(
            &challenger,
            timeout.as_millis().min(u32::MAX as u128) as u32,
        )?
        .context("Another new copy is already waiting; existing work was not interrupted")?;
        if acquire_owner(&owner, 0)? {
            // Transfer the acquired mutex to OwnerLock without releasing it.
            let owner = OwnerLock(owner);
            let _control =
                MutexLock::acquire(&control, INFINITE)?.context("Handoff control unavailable")?;
            unsafe {
                ResetEvent(request.0)?;
                ResetEvent(acknowledged.0)?;
            }
            drop(_control);
            drop(challenger_lock);
            return Ok(OwnerIpc {
                request,
                acknowledged,
                control,
                challenger,
                _owner: owner,
            });
        }

        let mut committed;
        {
            let _control =
                MutexLock::acquire(&control, INFINITE)?.context("Handoff control unavailable")?;
            unsafe {
                // A stale request may already have been acknowledged while this
                // contender acquired its slot. Preserve that commitment.
                committed = signaled(&acknowledged)?;
                SetEvent(request.0)?;
            }
        }
        loop {
            if acquire_owner(&owner, 100)? {
                let owner = OwnerLock(owner);
                let _control = MutexLock::acquire(&control, INFINITE)?
                    .context("Handoff control unavailable")?;
                unsafe {
                    ResetEvent(request.0)?;
                    ResetEvent(acknowledged.0)?;
                }
                drop(_control);
                drop(challenger_lock);
                return Ok(OwnerIpc {
                    request,
                    acknowledged,
                    control,
                    challenger,
                    _owner: owner,
                });
            }
            let _control =
                MutexLock::acquire(&control, INFINITE)?.context("Handoff control unavailable")?;
            if signaled(&acknowledged)? {
                committed = true;
            }
            if !committed && started.elapsed() >= timeout {
                // Cancellation and owner's acknowledgment use the same named
                // control mutex. Exactly one wins; never cancel after an ACK.
                unsafe {
                    ResetEvent(request.0)?;
                    ResetEvent(acknowledged.0)?;
                }
                bail!(
                    "Existing copy is still busy after 120 seconds; no work was interrupted. Try again after it finishes"
                );
            }
            // Never hold control while waiting for the owner's lifetime mutex.
            drop(_control);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_and_takeover_have_no_start_after_close_gap() {
        let mut state = GateState::default();
        state.begin().unwrap();
        assert_eq!(state.request(true), Control::Waiting);
        assert!(!state.closing);
        state.active -= 1;
        assert_eq!(state.request(true), Control::Close);
        assert!(state.begin().is_err());
    }

    #[test]
    fn cancelled_or_abandoned_request_does_not_poison_owner() {
        let mut state = GateState {
            active: 0,
            closing: true,
        };
        assert_eq!(state.request(false), Control::None);
        state.begin().unwrap();
        assert_eq!(state.active, 1);
    }

    #[test]
    fn multiple_worker_guards_must_all_finish() {
        let state = Arc::new(Mutex::new(GateState::default()));
        for _ in 0..2 {
            state.lock().unwrap().begin().unwrap();
        }
        let first = WorkGuard {
            state: state.clone(),
        };
        let second = WorkGuard {
            state: state.clone(),
        };
        drop(first);
        assert_eq!(state.lock().unwrap().request(true), Control::Waiting);
        drop(second);
        assert_eq!(state.lock().unwrap().request(true), Control::Close);
    }

    #[test]
    fn worker_guard_can_be_moved_into_worker() {
        fn is_send<T: Send>() {}
        is_send::<WorkGuard>();
    }

    #[cfg(windows)]
    fn test_owner(scope: &str) -> Result<Instance> {
        test_owner_timeout(scope, std::time::Duration::from_secs(3))
    }

    #[cfg(windows)]
    fn test_owner_timeout(scope: &str, timeout: std::time::Duration) -> Result<Instance> {
        Ok(Instance {
            state: Arc::new(Mutex::new(GateState::default())),
            ipc: native::coordinate_scoped(Some(scope), timeout)?,
            _thread_bound: PhantomData,
        })
    }

    /// Spawned only by the two integration tests with a unique private scope.
    /// An ordinary full-suite invocation does nothing and never touches GUI IPC.
    #[cfg(windows)]
    #[test]
    fn handoff_child_process() -> Result<()> {
        use std::{
            io::Write,
            time::{Duration, Instant},
        };
        let Ok(scope) = std::env::var("AMIGOOD_HANDOFF_TEST_SCOPE") else {
            return Ok(());
        };
        let busy = std::env::var("AMIGOOD_HANDOFF_TEST_BUSY").as_deref() == Ok("1");
        let cancel_case = std::env::var("AMIGOOD_HANDOFF_TEST_CANCEL").as_deref() == Ok("1");
        let owner = test_owner(&scope)?;
        let (finish, receive) = std::sync::mpsc::channel();
        let worker = if busy {
            let guard = owner.begin_work()?;
            Some(std::thread::spawn(move || {
                let _ = receive.recv_timeout(Duration::from_secs(6));
                println!("HANDOFF_WORK_FINISHED");
                let _ = std::io::stdout().flush();
                drop(guard);
            }))
        } else {
            None
        };
        println!("HANDOFF_READY");
        std::io::stdout().flush()?;
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut release_sent = false;
        let mut closed = false;
        let mut busy_observed = false;
        let mut cancellation_observed = None;
        let mut cancelled_cleanly = false;
        while Instant::now() < deadline {
            match owner.poll() {
                Control::None if cancel_case && busy_observed && !release_sent => {
                    println!("HANDOFF_CANCEL_CLEARED");
                    std::io::stdout().flush()?;
                    finish
                        .send(())
                        .map_err(|_| anyhow!("Test worker channel unavailable"))?;
                    release_sent = true;
                    cancellation_observed = Some(Instant::now());
                }
                Control::None => {}
                Control::Waiting if busy && !release_sent => {
                    if !busy_observed {
                        println!("HANDOFF_BUSY_OBSERVED");
                        std::io::stdout().flush()?;
                        busy_observed = true;
                    }
                    if !cancel_case {
                        finish
                            .send(())
                            .map_err(|_| anyhow!("Test worker channel unavailable"))?;
                        release_sent = true;
                    }
                }
                Control::Waiting => {}
                Control::Close => {
                    println!("HANDOFF_CLOSE");
                    std::io::stdout().flush()?;
                    closed = true;
                    break;
                }
            }
            if cancellation_observed.is_some_and(|at| at.elapsed() >= Duration::from_millis(200)) {
                println!("HANDOFF_STILL_OWNER");
                std::io::stdout().flush()?;
                cancelled_cleanly = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if let Some(worker) = worker {
            let _ = finish.send(());
            worker.join().map_err(|_| anyhow!("Test worker panicked"))?;
        }
        if !closed && !cancelled_cleanly {
            bail!("Test owner did not receive a cooperative close request");
        }
        Ok(())
    }

    #[cfg(windows)]
    fn multiprocess_handoff(busy: bool, cancel_case: bool) -> Result<()> {
        use std::{
            io::{BufRead, BufReader, Read},
            process::{Command, Stdio},
            time::{SystemTime, UNIX_EPOCH},
        };
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let scope = format!(
            "{}-{nonce}-{}",
            std::process::id(),
            if busy { "busy" } else { "idle" }
        );
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "instance::tests::handoff_child_process",
                "--nocapture",
            ])
            .env("AMIGOOD_HANDOFF_TEST_SCOPE", &scope)
            .env("AMIGOOD_HANDOFF_TEST_BUSY", if busy { "1" } else { "0" })
            .env(
                "AMIGOOD_HANDOFF_TEST_CANCEL",
                if cancel_case { "1" } else { "0" },
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut output = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| anyhow!("Test child stdout unavailable"))?,
        );
        let mut ready = false;
        let mut text = String::new();
        loop {
            let mut line = String::new();
            if output.read_line(&mut line)? == 0 {
                break;
            }
            ready = line.contains("HANDOFF_READY");
            text.push_str(&line);
            if ready {
                break;
            }
        }
        if !ready {
            let status = child.wait()?;
            bail!("Private handoff test child failed before readiness: {status}");
        }
        // This blocks until the old child's lifetime mutex is released. The
        // child has no GUI, repairs, network, files, or production IPC names.
        let owner = if cancel_case {
            let result = test_owner_timeout(&scope, std::time::Duration::from_millis(100));
            assert!(
                result.is_err(),
                "Busy contender unexpectedly took over before timeout"
            );
            None
        } else {
            Some(test_owner(&scope)?)
        };
        output.read_to_string(&mut text)?;
        let status = child.wait()?;
        assert!(status.success(), "Private handoff child failed: {text}");
        if cancel_case {
            assert!(
                text.contains("HANDOFF_CANCEL_CLEARED"),
                "No cancellation observed: {text}"
            );
            assert!(
                text.contains("HANDOFF_STILL_OWNER"),
                "Owner did not remain live: {text}"
            );
            assert!(
                !text.contains("HANDOFF_CLOSE"),
                "Cancelled request closed the owner: {text}"
            );
        } else {
            assert!(
                text.contains("HANDOFF_CLOSE"),
                "No cooperative close: {text}"
            );
        }
        if busy && !cancel_case {
            let waiting = text
                .find("HANDOFF_BUSY_OBSERVED")
                .expect("Busy handoff not observed");
            let finished = text
                .find("HANDOFF_WORK_FINISHED")
                .expect("Worker did not finish");
            let closed = text.find("HANDOFF_CLOSE").unwrap();
            assert!(
                waiting < finished && finished < closed,
                "Owner closed before worker finished: {text}"
            );
        }
        if let Some(owner) = owner {
            assert_eq!(owner.poll(), Control::None);
            owner.begin_work()?;
        }
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_idle_handoff() -> Result<()> {
        multiprocess_handoff(false, false)
    }

    #[cfg(windows)]
    #[test]
    fn windows_busy_handoff() -> Result<()> {
        multiprocess_handoff(true, false)
    }

    #[cfg(windows)]
    #[test]
    fn windows_cancelled_challenger_does_not_close_owner_later() -> Result<()> {
        multiprocess_handoff(true, true)
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_same_owner_same_integrity_world_writable_object() -> Result<()> {
        native::test_rejects_world_writable_object()
    }
}
