# ShamirSecretSharing
A C implementation of Shamir's Secret Sharing by David Madore

No dependencies. No dynamic memory allocation. No recursion. Small and Fast.

This is a thread safe C library version of [David Madore](http://www.madore.org/~david/)'s excellent comand line implementation of [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing).

## Merkle Tree Authentication

`sssMk.h` provides Merkle tree operations for authenticating individual shares. Each share can be independently verified against a root hash using a compact proof, without needing all other shares.

The hash function is pluggable via `sssMkHsh_t`, which provides allocate, initialize, update, finalize, and deallocate callbacks plus a hash size parameter h (hash is 2^h bytes).

### Build Tree

```c
unsigned char *sssMkHash(
  const sssMkHsh_t *h,
  const unsigned char *const *s,  /* n share data pointers */
  unsigned int l,                 /* share length in bytes */
  unsigned int n,                 /* number of shares (1..256) */
  unsigned char *w                /* work area (sssMkWaSz bytes) */
);
```

Returns pointer to root hash in work area, 0 on error. Internally pads to next power of 2 with zero hashes.

### Extract Proof

```c
unsigned char *sssMkProof(
  const sssMkHsh_t *h,
  unsigned int n,                 /* number of shares */
  unsigned int i,                 /* share index (0..n-1) */
  const unsigned char *w,         /* work area (from sssMkHash) */
  unsigned char *p                /* proof output (sssMkPfSz bytes) */
);
```

Returns pointer past proof, 0 on error. Proof size is ceil(log2(n)) hashes.

### Verify Share

```c
unsigned char *sssMkExtract(
  const sssMkHsh_t *h,
  const unsigned char *s,         /* share data */
  unsigned int l,                 /* share length */
  unsigned int i,                 /* share index */
  unsigned int n,                 /* total shares */
  const unsigned char *p,         /* proof (sssMkPfSz bytes) */
  unsigned char *w                /* work area (sssMkVfSz bytes) */
);
```

Returns pointer to computed root hash in work area, 0 on error. Caller compares returned hash with expected root.

### Size Functions

- `sssMkWaSz(h, n)` - work area for tree construction
- `sssMkPfSz(h, n)` - proof size per share
- `sssMkVfSz(h)` - work area for verification

## Examples

* test/main.c - [David Madore](http://www.madore.org/~david/)'s command line interface to the library
* test/sssMkTest.c - Merkle tree authentication test
