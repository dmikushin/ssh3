//! Server-wide memory budgets (SPEC §4 "Rings hold bytes, not reservations").
//!
//! A `Budget` is a counter with a cap; a `Permit` is an owned share of it
//! that is returned when the permit shrinks or is dropped (RAII), so a lane
//! that is dropped for any reason — completion, error, panic, session
//! expiry — gives its share back.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Notify;

#[derive(Debug)]
pub struct Budget {
    name: &'static str,
    cap: u64,
    used: AtomicU64,
    /// Woken whenever capacity is returned.
    pub(crate) freed: Notify,
}

impl Budget {
    pub fn new(name: &'static str, cap: u64) -> Arc<Self> {
        Arc::new(Self { name, cap, used: AtomicU64::new(0), freed: Notify::new() })
    }
    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn cap(&self) -> u64 {
        self.cap
    }
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }
    /// Take up to `want`; returns what was obtained (possibly 0).
    fn take_upto(&self, want: u64) -> u64 {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let got = want.min(self.cap.saturating_sub(cur));
            if got == 0 {
                return 0;
            }
            match self.used.compare_exchange_weak(cur, cur + got, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return got,
                Err(v) => cur = v,
            }
        }
    }
    fn give(&self, n: u64) {
        if n > 0 {
            self.used.fetch_sub(n, Ordering::AcqRel);
            self.freed.notify_waiters();
        }
    }
}

#[derive(Debug)]
pub struct Permit {
    budget: Arc<Budget>,
    amount: u64,
}

impl Permit {
    pub fn empty(budget: Arc<Budget>) -> Self {
        Self { budget, amount: 0 }
    }
    pub fn amount(&self) -> u64 {
        self.amount
    }
    pub fn budget(&self) -> &Arc<Budget> {
        &self.budget
    }
    /// Grow by up to `want`; returns the amount obtained.
    pub fn grow_upto(&mut self, want: u64) -> u64 {
        let got = self.budget.take_upto(want);
        self.amount += got;
        got
    }
    pub fn shrink(&mut self, n: u64) {
        let n = n.min(self.amount);
        self.amount -= n;
        self.budget.give(n);
    }
    /// Move `n` (≤ amount) into a new permit of the same budget; no change
    /// to the budget's total.
    pub fn split(&mut self, n: u64) -> Permit {
        assert!(n <= self.amount, "split {n} from a permit of {}", self.amount);
        self.amount -= n;
        Permit { budget: self.budget.clone(), amount: n }
    }
    /// Take exactly `n` from the budget or nothing.
    pub fn try_new(budget: &Arc<Budget>, n: u64) -> Option<Permit> {
        let mut p = Permit::empty(budget.clone());
        if p.grow_upto(n) == n {
            Some(p)
        } else {
            None // dropping `p` returns any partial amount
        }
    }
    pub fn set(&mut self, target: u64) -> u64 {
        if target > self.amount {
            self.grow_upto(target - self.amount);
        } else {
            self.shrink(self.amount - target);
        }
        self.amount
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.budget.give(self.amount);
    }
}
