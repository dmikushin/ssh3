//! Chunked byte rings whose storage is charged to a budget (SPEC §4
//! "Budgets are charged on allocations, not on bytes").
//!
//! Storage is allocated in fixed 16 KiB chunks. Each chunk owns a budget
//! permit (shared by the slices cut from it) that is returned only when the
//! last slice of the chunk is dropped — never when its bytes are merely
//! consumed. Reads from QUIC or the local source go directly into the spare
//! part of a reserved chunk (`Tail`), so there is no unaccounted buffer.
//!
//! **No chunk memory leaves the ring detached from its permit.** The only
//! way out is [`ChunkSlice`], which carries the chunk's permit with the bytes
//! and exposes nothing but `&[u8]`; a slice held across an `.await` (QUIC
//! write, local sink write, replay after resume) keeps the chunk charged even
//! if the ring drained it meanwhile.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::{Bytes, BytesMut};

use crate::budget::Permit;

pub const CHUNK: usize = 16 * 1024;

/// The permit backing one chunk. A floor chunk also decrements its lane's
/// floor-chunk count when released.
pub(crate) struct ChunkPermit {
    pub(crate) _permit: Permit,
    pub(crate) floor: Option<Arc<AtomicU32>>,
}

impl Drop for ChunkPermit {
    fn drop(&mut self) {
        if let Some(f) = &self.floor {
            f.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Unfilled remainder of the current chunk.
pub(crate) struct Tail {
    buf: BytesMut,
    owner: Arc<ChunkPermit>,
}

impl Tail {
    pub(crate) fn new(owner: ChunkPermit) -> Self {
        Self { buf: BytesMut::zeroed(CHUNK), owner: Arc::new(owner) }
    }
    pub(crate) fn space(&self) -> usize {
        self.buf.len()
    }
    pub(crate) fn spare(&mut self, n: usize) -> &mut [u8] {
        &mut self.buf[..n]
    }
    /// Charged to the floor pool rather than a budget.
    pub(crate) fn is_floor(&self) -> bool {
        self.owner.floor.is_some()
    }
    /// Reclaim the reservation-derived `Permit` from a never-committed tail,
    /// so an aborted acquisition can fold it back into the lane reserve
    /// instead of returning it to the shared budget. Returns `None` for a
    /// floor tail (whose storage is the floor pool, not a budget permit) and
    /// for a tail whose chunk was already shared (committed), which never
    /// happens on the rollback path. On `Some`, the chunk's floor counter — if
    /// any — is released by dropping the leftover `ChunkPermit`.
    pub(crate) fn into_reserve_permit(self) -> Option<Permit> {
        // A fresh tail from `recv_chunk`/`take_tail` is the sole owner.
        let mut owner = Arc::try_unwrap(self.owner).ok()?;
        if owner.floor.is_some() {
            return None; // floor chunk: dropping `owner` decrements rfloor
        }
        // Move the permit out, leaving a zero-amount permit on the same budget
        // so `owner`'s Drop (floor is None) is a no-op. The returned permit
        // carries the full CH charge to be folded back into the lane reserve.
        let budget = owner._permit.budget().clone();
        Some(std::mem::replace(&mut owner._permit, Permit::empty(budget)))
    }
}

/// Bytes of one chunk together with the chunk's permit. Deliberately offers
/// no way to take the `Bytes` out.
pub(crate) struct ChunkSlice {
    bytes: Bytes,
    _owner: Arc<ChunkPermit>,
}

impl std::ops::Deref for ChunkSlice {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Default)]
pub(crate) struct Ring {
    segs: VecDeque<(Bytes, Arc<ChunkPermit>)>,
    len: usize,
    tail: Option<Tail>,
}

impl Ring {
    pub(crate) fn len(&self) -> usize {
        self.len
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Space left in the current tail chunk (0 if none).
    pub(crate) fn tail_space(&self) -> usize {
        self.tail.as_ref().map_or(0, Tail::space)
    }
    /// Take the tail out to read into it without holding the lane lock.
    pub(crate) fn take_tail(&mut self) -> Option<Tail> {
        self.tail.take()
    }
    /// Put a previously-taken tail back UNCHANGED (no bytes committed). Used to
    /// roll back an aborted acquisition: the ring must end exactly as it was,
    /// including the tail's spare capacity. There must be no current tail (the
    /// acquisition took it out first).
    pub(crate) fn restore_tail(&mut self, t: Tail) {
        debug_assert!(self.tail.is_none(), "restore_tail over an existing tail");
        self.tail = Some(t);
    }
    /// Put a tail back after `n` bytes were read into its front.
    pub(crate) fn commit(&mut self, mut t: Tail, n: usize) {
        if n > 0 {
            let seg = t.buf.split_to(n).freeze();
            self.segs.push_back((seg, t.owner.clone()));
            self.len += n;
        }
        if t.buf.is_empty() {
            drop(t); // the segments keep the chunk alive
        } else {
            self.tail = Some(t);
        }
    }
    /// Up to `max` bytes starting `off` bytes into the ring, as one
    /// zero-copy slice of a single segment, still charged to its chunk.
    pub(crate) fn peek(&self, mut off: usize, max: usize) -> Option<ChunkSlice> {
        for (b, owner) in &self.segs {
            if off < b.len() {
                let end = b.len().min(off + max);
                return Some(ChunkSlice { bytes: b.slice(off..end), _owner: owner.clone() });
            }
            off -= b.len();
        }
        None
    }
    /// Discard `n` bytes from the front; whole segments are dropped (and with
    /// the last one, the chunk and its permit).
    pub(crate) fn drain(&mut self, mut n: usize) {
        assert!(n <= self.len, "drain {n} from a ring of {}", self.len);
        self.len -= n;
        while n > 0 {
            let front = self.segs.front_mut().expect("ring length accounting");
            if front.0.len() <= n {
                n -= front.0.len();
                self.segs.pop_front();
            } else {
                let _ = front.0.split_to(n);
                n = 0;
            }
        }
    }
    /// An empty ring keeps its spare tail chunk for the next bytes; when the
    /// lane's credit drops, a budget-charged spare is returned (an idle lane
    /// holds only floor storage, SPEC §4).
    pub(crate) fn release_budget_tail(&mut self) {
        if self.len == 0 && self.tail.as_ref().is_some_and(|t| !t.is_floor()) {
            self.tail = None;
        }
    }

    /// Drop everything, including the tail.
    pub(crate) fn clear(&mut self) {
        self.segs.clear();
        self.len = 0;
        self.tail = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{Budget, Permit};

    /// Reviewer's repro: a slice handed out by the ring must keep its
    /// chunk's budget charge alive for as long as the slice lives.
    #[test]
    fn peek_slice_keeps_chunk_budget_charged() {
        let budget = Budget::new("review", CHUNK as u64);
        let permit = Permit::try_new(&budget, CHUNK as u64).unwrap();
        let mut tail = Tail::new(ChunkPermit { _permit: permit, floor: None });
        tail.spare(CHUNK).fill(0x42);
        let mut ring = Ring::default();
        ring.commit(tail, CHUNK);
        let slice = ring.peek(0, CHUNK).unwrap();
        ring.drain(CHUNK);
        assert_eq!(slice[CHUNK - 1], 0x42);
        assert_eq!(budget.used(), CHUNK as u64, "live zero-copy slice lost its chunk permit");
        drop(slice);
        assert_eq!(budget.used(), 0);
    }
}
