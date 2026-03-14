/*
 * ShamirSecretSharing - Merkle tree authentication for secret shares
 * Copyright (C) 2025 G. David Butler <gdb@dbSystems.com>
 *
 * This file is part of ShamirSecretSharing
 *
 * ShamirSecretSharing is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ShamirSecretSharing is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SSSMK_H
#define SSSMK_H

/*
 * Merkle tree for authenticating Shamir secret shares.
 *
 * Arbitrary share count n (1..256), internally padded to next power of 2.
 * Proof size is ceil(log2(n)) hashes.
 */

/* Hash context for Merkle tree operations */
typedef struct {
  void *(*a)(void);                                       /* hashContext allocate */
  void (*i)(void *);                                      /* hashContext initialize */
  void (*u)(void *, const unsigned char *, unsigned int); /* hashContext update */
  void (*f)(void *, unsigned char *);                     /* hashContext finalize */
  void (*d)(void *);                                      /* hashContext deallocate */
  unsigned char h;                                        /* (2^h) bytes per hash */
} sssMkHsh_t;

/*
 * Return size, in bytes, of Merkle tree work area, 0 on error.
 * h: (2^h) bytes per hash
 * n: number of shares (1..256)
 */
unsigned int
sssMkWaSz(
  unsigned char h
 ,unsigned int n
);

/*
 * Return size, in bytes, of Merkle proof, 0 on error.
 * h: (2^h) bytes per hash
 * n: number of shares (1..256)
 */
unsigned int
sssMkPfSz(
  unsigned char h
 ,unsigned int n
);

/*
 * Return size, in bytes, of verify work area.
 * h: (2^h) bytes per hash
 */
unsigned int
sssMkVfSz(
  unsigned char h
);

/*
 * Build Merkle tree over n shares, return pointer to root hash in
 * work area, 0 on error.
 */
unsigned char *
sssMkHash(
  const sssMkHsh_t *h
 ,const unsigned char *const *s /* n share data pointers */
 ,unsigned int l                /* share length in bytes */
 ,unsigned int n                /* number of shares (1..256) */
 ,unsigned char *w              /* work area (sssMkWaSz) */
);

/*
 * Extract Merkle proof for share i from built tree.
 * Return pointer past proof, 0 on error.
 */
unsigned char *
sssMkProof(
  const sssMkHsh_t *h
 ,unsigned int n                /* number of shares */
 ,unsigned int i                /* share index (0..n-1) */
 ,const unsigned char *w        /* work area (from sssMkHash) */
 ,unsigned char *p              /* proof output (sssMkPfSz) */
);

/*
 * Extract root hash from share and Merkle proof.
 * Return pointer to root hash in work area, 0 on error.
 * Caller compares returned hash with expected root.
 */
unsigned char *
sssMkExtract(
  const sssMkHsh_t *h
 ,const unsigned char *s        /* share data */
 ,unsigned int l                /* share length */
 ,unsigned int i                /* share index */
 ,unsigned int n                /* total shares */
 ,const unsigned char *p        /* proof (sssMkPfSz) */
 ,unsigned char *w              /* work area (sssMkVfSz) */
);

#endif /* SSSMK_H */
