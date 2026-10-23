//! Chunked byte rings whose storage is charged to a budget (SPEC §4
//! "Budgets are charged on allocations, not on bytes").
//!
//! Storage is allocated in fixed 16 KiB chunks. Each chunk owns a budget
//! permit (shared by the slices cut from it) that is returned only when the
//! last slice of the chunk is dropped — never when its bytes are merely
//! consumed. Reads from QUIC or the local source go directly into the spare
//! part of a reserved chunk (`Tail`), so there is no unaccounted buffer.

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
    /// zero-copy slice of a single segment.
    pub(crate) fn peek(&self, mut off: usize, max: usize) -> Option<Bytes> {
        for (b, _) in &self.segs {
            if off < b.len() {
                let end = b.len().min(off + max);
                return Some(b.slice(off..end));
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
    /// Drop everything, including the tail.
    pub(crate) fn clear(&mut self) {
        self.segs.clear();
        self.len = 0;
        self.tail = None;
    }
}
