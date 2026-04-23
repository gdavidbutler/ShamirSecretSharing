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

#include "sssMk.h"

/* Domain separation tags: distinguish leaf, internal-node and root hash
 * inputs. Prefixing rules out leaf/node/root confusion from second-preimage
 * attacks. The root hash additionally commits to the share count n so
 * proofs cannot be replayed between trees of different sizes that share
 * the same padded-tree structure. */
static const unsigned char LeafTag = 0x00;
static const unsigned char NodeTag = 0x01;
static const unsigned char RootTag = 0x02;

/* next power of 2 >= n, for n in 1..256 */
static unsigned int
nextPow2(
  unsigned int n
){
  unsigned int p;

  for (p = 1; p < n; p <<= 1)
    ;
  return (p);
}

/* log2(p) for p that is a power of 2 */
static unsigned int
log2p(
  unsigned int p
){
  unsigned int d;

  for (d = 0; (1U << d) < p; ++d)
    ;
  return (d);
}

unsigned int
sssMkWaSz(
  unsigned char h
 ,unsigned int n
){
  unsigned int p;

  if (n < 1 || n > 256)
    return (0);
  p = nextPow2(n);
  /* 2*p hash-sized slots (index 0 unused, 1..2p-1 are tree nodes) */
  return (p << (h + 1));
}

unsigned int
sssMkPfSz(
  unsigned char h
 ,unsigned int n
){
  unsigned int p;

  if (n < 1 || n > 256)
    return (0);
  p = nextPow2(n);
  /* one sibling hash per tree level */
  return (log2p(p) << h);
}

unsigned int
sssMkVfSz(
  unsigned char h
){
  /* current hash (2^h) */
  return (1U << h);
}

unsigned char *
sssMkHash(
  const sssMkHsh_t *h
 ,const unsigned char *const *s
 ,unsigned int l
 ,unsigned int n
 ,unsigned char *w
){
  void *c;
  unsigned int p;
  unsigned int b;
  unsigned int i;
  unsigned int j;
  unsigned char *np;
  unsigned char *cp;
  unsigned char nb[2];

  if (!h || !s || !l || n < 1 || n > 256 || !w
   || !h->a || !h->i || !h->u || !h->f)
    return (0);
  b = 1U << h->h;
  p = nextPow2(n);
  if (!(c = h->a()))
    return (0);

  /* hash real share leaves with LeafTag prefix */
  np = w + p * b;
  for (i = 0; i < n; ++i) {
    h->i(c);
    h->u(c, &LeafTag, 1);
    h->u(c, s[i], l);
    h->f(c, np);
    np += b;
  }

  /* zero padding leaves (never addressable via Extract: i >= n is rejected) */
  for (i = n; i < p; ++i)
    for (j = 0; j < b; ++j)
      *np++ = 0;

  /* build tree bottom-up: tree[i] = H(NodeTag || tree[2i] || tree[2i+1]) */
  np = w + (p - 1) * b;
  cp = np + (p - 1) * b;
  for (i = p - 1; i > 0; --i) {
    h->i(c);
    h->u(c, &NodeTag, 1);
    h->u(c, cp, b << 1);
    h->f(c, np);
    np -= b;
    cp -= b << 1;
  }

  /* bind n to root: slot 0 = H(RootTag || n_hi || n_lo || tree[1]) */
  nb[0] = (unsigned char)(n >> 8);
  nb[1] = (unsigned char)(n & 0xff);
  h->i(c);
  h->u(c, &RootTag, 1);
  h->u(c, nb, 2);
  h->u(c, w + b, b);
  h->f(c, w);

  if (h->d)
    h->d(c);
  return (w); /* bound root at slot 0 */
}

unsigned char *
sssMkProof(
  const sssMkHsh_t *h
 ,unsigned int n
 ,unsigned int i
 ,const unsigned char *w
 ,unsigned char *pf
){
  unsigned int pw;
  unsigned int b;
  unsigned int node;
  unsigned int j;
  const unsigned char *sp;

  if (!h || n < 1 || n > 256 || i >= n || !w || !pf)
    return (0);
  b = 1U << h->h;
  pw = nextPow2(n);
  node = pw + i;

  /* walk from leaf to root, copying sibling hashes */
  while (node > 1) {
    sp = w + (node ^ 1) * b;
    for (j = 0; j < b; ++j)
      *pf++ = sp[j];
    node >>= 1;
  }
  return (pf);
}

unsigned char *
sssMkExtract(
  const sssMkHsh_t *h
 ,const unsigned char *s
 ,unsigned int l
 ,unsigned int i
 ,unsigned int n
 ,const unsigned char *pf
 ,unsigned char *w
){
  void *c;
  unsigned int pw;
  unsigned int b;
  unsigned int node;
  unsigned char *cur;
  const unsigned char *lo;
  const unsigned char *hi;
  unsigned char nb[2];

  if (!h || !s || !l || n < 1 || n > 256 || i >= n || !pf || !w
   || !h->a || !h->i || !h->u || !h->f)
    return (0);
  b = 1U << h->h;
  pw = nextPow2(n);
  cur = w;

  if (!(c = h->a()))
    return (0);

  /* hash share data with LeafTag to get leaf hash */
  h->i(c);
  h->u(c, &LeafTag, 1);
  h->u(c, s, l);
  h->f(c, cur);

  /* walk up the tree, combining with proof siblings */
  node = pw + i;
  while (node > 1) {
    if (node & 1) {
      lo = pf; hi = cur;  /* right child: sibling is left */
    } else {
      lo = cur; hi = pf;  /* left child: sibling is right */
    }
    pf += b;
    h->i(c);
    h->u(c, &NodeTag, 1);
    h->u(c, lo, b);
    h->u(c, hi, b);
    h->f(c, cur);
    node >>= 1;
  }

  /* bind n: cur = H(RootTag || n_hi || n_lo || inner_root) */
  nb[0] = (unsigned char)(n >> 8);
  nb[1] = (unsigned char)(n & 0xff);
  h->i(c);
  h->u(c, &RootTag, 1);
  h->u(c, nb, 2);
  h->u(c, cur, b);
  h->f(c, cur);

  if (h->d)
    h->d(c);
  return (cur);
}
