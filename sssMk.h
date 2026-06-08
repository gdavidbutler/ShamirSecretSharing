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

/* Generated with Claude Code (https://claude.ai/code) */

#ifndef SSSMK_H
#define SSSMK_H

/*
 * Merkle tree for authenticating Shamir secret shares.
 *
 * Arbitrary share count n (1..256), internally padded to next power of 2.
 * Proof size is ceil(log2(n)) hashes.
 *
 * Leaf hash:  H(0x00 || ocp || share_data)
 * Node hash:  H(0x01 || left_child || right_child)
 * Root hash:  H(0x02 || scp || n_hi || n_lo || inner_root)
 * The tag byte prefix prevents leaf/node/root confusion. The leaf binds
 * each share to its output code point (ocp), so a share value cannot be
 * replayed under a different code point. The root binds the secret code
 * point (scp) and the share count n: a proof valid for (i, n, scp) is not
 * valid for (i, n', scp') when n != n' or scp != scp', so shares cannot be
 * replayed between trees of different sizes or different secret points that
 * happen to share a padded-tree structure.
 *
 * Caller should zero the tree work area when done; it retains leaf hashes
 * H(0x00 || ocp || share) for every share.
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
 ,unsigned char scp             /* secret code point (bound at root) */
 ,const unsigned char *op       /* n output code points (op[i] bound in leaf i) */
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
 ,unsigned char *pf             /* proof output (sssMkPfSz) */
);

/*
 * Extract root hash from share and Merkle proof.
 * n must equal the value passed to sssMkHash and sssMkProof.
 * Return pointer to root hash in work area, 0 on error.
 * Caller compares returned hash with expected root (use a constant-time
 * compare if the comparison is security-sensitive).
 */
unsigned char *
sssMkExtract(
  const sssMkHsh_t *h
 ,unsigned char scp             /* secret code point (must match sssMkHash) */
 ,unsigned char ocp             /* this share's output code point */
 ,const unsigned char *s        /* share data */
 ,unsigned int l                /* share length */
 ,unsigned int i                /* share index */
 ,unsigned int n                /* total shares */
 ,const unsigned char *pf       /* proof (sssMkPfSz) */
 ,unsigned char *w              /* work area (sssMkVfSz) */
);

#endif /* SSSMK_H */
