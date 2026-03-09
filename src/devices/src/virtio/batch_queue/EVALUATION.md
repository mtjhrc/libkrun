# Batch Queue Evaluation

## Summary

The current design is a clear improvement over the old `Vec<Vec<iovec>>` / custom-repr split:

- raw iovecs live in one shared contiguous arena
- per-chain metadata stores only ranges into that arena
- user-transformed state is separate and generic
- pointer-bearing syscall headers like `mmsghdr` / `msghdr_x` are owned by the transformed state, not by callback-local scratch

This is the right shape for the current `writev` / `readv` paths and for the `unixgram` `sendmmsg` / `recvmmsg` use case.

The design is not allocation-free in the absolute sense, but it is close to that after warm-up. The biggest remaining gap is API flexibility for future "one batch item covers multiple chains" transforms.

## Safety

### What is good

- Header pointers do not escape the owner anymore.
- `MsgHdrItem` owns the syscall headers, and those headers point only into the queue-owned raw-iovec arena.
- The raw iovec arena uses explicit relocation points. If it grows or compacts, transformed state is repaired immediately via `WorkItemState::fixup_iovecs`.
- The syscall backends only borrow header slices during the callback. They do not cache pointers after the borrow ends.
- The main alias-sensitive backing is no longer hidden inside many independent `Vec`s.

### Unsafe surface

The design is still fundamentally `unsafe`, but the unsafe surface is smaller and more explicit:

- `RawIovecArray` manually allocates, copies, and deallocates memory.
- `raw_as_io_slices` / `raw_as_io_slices_mut` reinterpret `RawAliasedIoSlice` as typed iovec wrappers.
- guest-memory-backed raw pointers are lifetime-erased and later reborrowed.
- transformed state may hold raw pointers and must rebuild them correctly in `fixup_iovecs`.

### Main invariants

The current approach is safe only if these invariants hold:

1. Every live `WorkItem` range points into the current raw-iovec arena.
2. Any arena movement is followed by complete transformed-state fixup before headers are borrowed again.
3. No transformed state keeps pointers anywhere except into the raw-iovec arena it is fixed up against.
4. The queue never mutates the transformed array while a syscall is using a borrowed slice from it.
5. `advance` and `truncate` keep each live iovec range internally valid.

### Risk assessment

Overall: reasonably safe for this codebase, but not "trivially safe".

Why:

- The dangerous part is concentrated in one place now, which is good.
- The design avoids the earlier invalid-pointer problem.
- But the correctness still depends on carefully maintained invariants around manual allocation and pointer fixup.

I would describe it as:

- safer than the previous custom-repr system
- safe enough to build on
- still deserving more invariant documentation and targeted tests

## Allocations On The Hot Path

### Good

- There is no per-chain `Vec<iovec>` allocation anymore.
- `unixgram` does not allocate temporary syscall header scratch inside each callback.
- The raw-iovec arena is amortized and reused.
- The transformed array is amortized and reused.
- Compaction uses copies/memmoves, not new allocations.

### Still possible

Allocations can still happen in these cases:

- the raw-iovec arena grows
- the transformed `Vec<T>` grows

So the honest answer is:

- cold/warm-up path: allocations can happen
- steady state with enough capacity: usually no allocations on the fast path

### Performance observations

- Arena growth is explicit and therefore predictable, which is good.
- Front compaction is not free: it does a memmove of remaining iovecs.
- `Vec::drain(..count)` on work items / transformed state also shifts elements.
- The transform path itself now streams from an iterator into the shared arena, so there is no temporary per-chain iovec container to spill.

If "no allocations after setup" becomes a hard requirement, the next obvious additions are:

- an explicit reserve API for the raw-iovec arena
- an explicit reserve API for transformed-state capacity

## API Usage

### What is simple now

For plain backends (`tap`, `unixstream`):

- `feed()` / `feed_with_transform()` stay straightforward
- `io_slices()` and `io_slices_mut()` are easy to use
- partial advance / truncate still work

For `unixgram`:

- the backend owns real `MsgHdrItem`s
- the syscall sees a contiguous header slice
- headers are repaired from the current shared iovec storage

That is much simpler than the old "custom chain repr owns its own backing" model.

### Why the separate transformed array is the right choice

Keeping transformed state out of `WorkItem` is correct.

If transformed state were embedded inside `WorkItem`, then `mmsghdr` / `msghdr_x` items would not be stored as one contiguous array unless `WorkItem` itself became the syscall element layout. That would make the queue metadata layout much more awkward and less reusable.

The current split gives:

- contiguous raw iovecs
- contiguous transformed syscall headers
- separate queue metadata

That is the right decomposition for the current problem.

## API Flexibility

### Strengths

- Transformed state is generic.
- Pointer-owning transformed state is supported.
- Default backends do not pay for syscall-header-specific machinery.
- The queue controls the raw-iovec lifetime centrally.

### Current limitation

The current API is still fundamentally "one transformed item per chain".

That is the main limitation.

It works well for:

- one `writev` per chain
- one `readv` per chain
- one `mmsghdr` / `msghdr_x` per chain

It does not yet naturally model:

- one batch item spanning multiple chains
- merged TX submission of two or more chain payloads
- a transform pass that consumes a window of chains and emits a different number of batch items

### Why this matters

The user-facing goal was not just to remove allocations, but also to keep the design open for future chain merging. The current design helps with that by centralizing raw iovecs, but it does not solve it yet at the API level.

The main missing abstraction is a higher-level batch item that can cover:

- a contiguous range of source `WorkItem`s
- a contiguous or piecewise range in the raw-iovec arena
- one transformed state object describing that merged submission unit

Right now, `WorkItemState::fixup_iovecs(&[RawAliasedIoSlice])` only sees one chain's live slice. That is enough for `MsgHdrItem`, but it is not enough for a future merged-chain item.

## Bottom Line

### Safety

Good, with explicit unsafe boundaries. Safer than before, but still needs discipline.

### Allocation behavior

Good after warm-up. Not strictly allocation-free yet, but no longer allocation-heavy in the hot path.

### API usability

Good for current backends. Much simpler than the old repr/pool trait stack.

### API flexibility

Adequate for per-chain transforms. Not yet sufficient for true multi-chain batch items.

## Recommended Next Steps

1. Document the unsafe invariants directly in code next to `RawIovecArray`, `IovecStorage`, and `WorkItemState`.
2. Add focused tests for arena growth + pointer fixup under `unixgram`.
3. Add explicit reserve methods so steady-state no-allocation behavior can be guaranteed earlier.
4. If merged-chain batching is still a goal, add a second abstraction above `WorkItem` rather than overloading the current 1:1 transformed-state model.
