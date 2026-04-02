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
  /* current hash (2^h) + combined buffer (2^(h+1)) */
  return (3U << h);
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

  if (!h || !s || !l || n < 1 || n > 256 || !w
   || !h->a || !h->i || !h->u || !h->f)
    return (0);
  b = 1U << h->h;
  p = nextPow2(n);
  if (!(c = h->a()))
    return (0);

  /* hash real share leaves */
  np = w + p * b;
  for (i = 0; i < n; ++i) {
    h->i(c);
    h->u(c, s[i], l);
    h->f(c, np);
    np += b;
  }

  /* zero padding leaves */
  for (i = n; i < p; ++i)
    for (j = 0; j < b; ++j)
      *np++ = 0;

  /* build tree bottom-up: tree[i] = hash(tree[2i] || tree[2i+1]) */
  np = w + (p - 1) * b;
  cp = np + (p - 1) * b;
  for (i = p - 1; i > 0; --i) {
    h->i(c);
    h->u(c, cp, b << 1);
    h->f(c, np);
    np -= b;
    cp -= b << 1;
  }

  if (h->d)
    h->d(c);
  return (w + b); /* tree[1] = root */
}

unsigned char *
sssMkProof(
  const sssMkHsh_t *h
 ,unsigned int n
 ,unsigned int i
 ,const unsigned char *w
 ,unsigned char *p
){
  unsigned int pw;
  unsigned int b;
  unsigned int node;
  unsigned int j;
  const unsigned char *sp;

  if (!h || n < 1 || n > 256 || i >= n || !w || !p)
    return (0);
  b = 1U << h->h;
  pw = nextPow2(n);
  node = pw + i;

  /* walk from leaf to root, copying sibling hashes */
  while (node > 1) {
    sp = w + (node ^ 1) * b;
    for (j = 0; j < b; ++j)
      *p++ = sp[j];
    node >>= 1;
  }
  return (p);
}

unsigned char *
sssMkExtract(
  const sssMkHsh_t *h
 ,const unsigned char *s
 ,unsigned int l
 ,unsigned int i
 ,unsigned int n
 ,const unsigned char *p
 ,unsigned char *w
){
  void *c;
  unsigned int pw;
  unsigned int b;
  unsigned int node;
  unsigned int j;
  unsigned char *cur;
  unsigned char *cmb;
  const unsigned char *lo;
  const unsigned char *hi;

  if (!h || !s || !l || n < 1 || n > 256 || i >= n || !p || !w
   || !h->a || !h->i || !h->u || !h->f)
    return (0);
  b = 1U << h->h;
  pw = nextPow2(n);
  cur = w;
  cmb = w + b;

  if (!(c = h->a()))
    return (0);

  /* hash share data to get leaf hash */
  h->i(c);
  h->u(c, s, l);
  h->f(c, cur);

  /* walk up the tree, combining with proof siblings */
  node = pw + i;
  while (node > 1) {
    if (node & 1) {
      lo = p; hi = cur;   /* right child: sibling is left */
    } else {
      lo = cur; hi = p;   /* left child: sibling is right */
    }
    for (j = 0; j < b; ++j)
      cmb[j] = lo[j];
    for (j = 0; j < b; ++j)
      cmb[b + j] = hi[j];
    p += b;
    h->i(c);
    h->u(c, cmb, b << 1);
    h->f(c, cur);
    node >>= 1;
  }

  if (h->d)
    h->d(c);
  return (cur);
}
