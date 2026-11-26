//! Test-only crash and storage-failure injection. Compiled to no-ops outside
//! `cfg(test)`.

/// Abort the process (no destructors, no flushing) when the environment
/// variable `MR_PRIVATE_CRASH_AT` names this point.
#[cfg(test)]
pub fn crash(point: &str) {
    if std::env::var("MR_PRIVATE_CRASH_AT").ok().as_deref() == Some(point) {
        eprintln!("crash-injection: aborting at {point}");
        std::process::abort();
    }
}

#[cfg(not(test))]
#[inline(always)]
pub fn crash(_point: &str) {}

#[cfg(test)]
thread_local! {
    static FAIL_AT: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Make the next `fail(point)` on this thread return an error.
#[cfg(test)]
pub fn arm(point: &str) {
    FAIL_AT.with(|f| *f.borrow_mut() = Some(point.to_string()));
}

/// Simulated storage failure at `point` (one-shot, per thread).
#[cfg(test)]
pub fn fail(point: &str) -> Result<(), super::store::StoreError> {
    FAIL_AT.with(|f| {
        let mut f = f.borrow_mut();
        if f.as_deref() == Some(point) {
            *f = None;
            Err(super::store::StoreError(format!(
                "injected failure at {point}"
            )))
        } else {
            Ok(())
        }
    })
}

#[cfg(not(test))]
#[inline(always)]
pub fn fail(_point: &str) -> Result<(), super::store::StoreError> {
    Ok(())
}

// Test-only pause points, armed per thread: `arm_pause(point)` (called on
// the thread that will reach the point) returns a receiver signalled when
// that thread reaches `pause(point)`, which then sleeps briefly so another
// thread can act in exactly that interval. One-shot.
#[cfg(test)]
thread_local! {
    static PAUSES: std::cell::RefCell<Vec<(String, std::sync::mpsc::Sender<()>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub fn arm_pause(point: &str) -> std::sync::mpsc::Receiver<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    PAUSES.with(|p| p.borrow_mut().push((point.to_string(), tx)));
    rx
}

#[cfg(test)]
pub fn pause(point: &str) {
    let hit = PAUSES.with(|p| {
        let mut p = p.borrow_mut();
        p.iter().position(|(n, _)| n == point).map(|i| p.remove(i))
    });
    if let Some((_, tx)) = hit {
        let _ = tx.send(());
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

#[cfg(not(test))]
#[inline(always)]
pub fn pause(_point: &str) {}
