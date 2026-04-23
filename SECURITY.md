# Security Policy

## Reporting

Report security issues by opening a GitHub issue.

## Threat model and known limitations

### Cache-timing side channel in `sss()`

The core interpolation in `sss.c` uses data-dependent lookups into a 64 KB
Conway multiplication table (`Cmt[256][256]`). The table is far larger than
typical L1 data caches, so the cache-line access pattern during sharing is a
function of the secret bytes. An adversary co-resident on the CPU (SMT
sibling, same-host VM, JavaScript sandbox, etc.) can recover secret bytes
through cache-timing measurement. This is the same class of attack used to
break early table-based AES implementations.

Recovery from shares leaks the share bytes (not the reconstructed secret)
through the same channel; this is usually less sensitive because shares are
already shared material.

Mitigations for callers:

- Isolate the code that handles secrets from untrusted co-tenants
  (dedicated physical core, no SMT sharing, no guest VMs).
- Keep secrets in RAM for as short a time as possible.
- A bitsliced or carry-less-multiplication implementation would remove
  this channel, at the cost of larger code and loss of the original
  portability guarantee. The current library does not offer one.

### Work-area residue

`sssMkHash` leaves `H(0x00 || share_i)` for every share in the tree work
area. Callers should zero the work area when done. The shares themselves
are not in the work area, and a preimage attack on the hash function is
infeasible for any sound hash.

### Constant-time root comparison

`sssMkExtract` returns a hash pointer; the caller is responsible for the
comparison against the expected root. Use a constant-time comparison
(e.g. `x = 0; for (i = 0; i < b; ++i) x |= a[i] ^ e[i];` then test `x == 0`)
if the tree is verifying shares received from an adversary that may time
the response.

### `n` binding

Since the commit of this document, the Merkle root commits to `n` (share
count) via a final `H(RootTag || n_hi || n_lo || inner_root)` hash. Proofs
produced with one `n` do not verify under a different `n`. Roots produced
by earlier versions of `sssMk` are **not** compatible with the current
verifier.
