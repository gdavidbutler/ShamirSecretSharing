/*
 * ShamirSecretSharing - Merkle tree authentication test
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sss.h"
#include "sssMk.h"
#include "rmd128.h"
#include "sha256.h"

static void *
rmd128Allocate(
  void
){
  return (malloc(rmd128tsize()));
}

static void *
sha256Allocate(
  void
){
  return (malloc(sha256tsize()));
}

/* Parametric test over (hash vtable, share count).
 * Builds a tree of n synthetic shares, verifies every share, then runs
 * six negative tests: bit-flip corruption, wrong-index substitution,
 * wrong-n substitution (larger), wrong-n substitution (smaller when valid),
 * wrong-ocp substitution (relabel), wrong-scp substitution.
 * Returns 0 on success, non-zero on any failure. */
static int
parametricTest(
  const sssMkHsh_t *h
 ,const char *hashName
 ,unsigned int n
){
  enum { ShareLen = 64 };
  unsigned int b;
  unsigned int waSz;
  unsigned int pfSz;
  unsigned int i;
  unsigned int j;
  unsigned char **shares;
  const unsigned char **cShares;
  unsigned char **proofs;
  unsigned char *work;
  unsigned char *root;
  unsigned char *savedRoot;
  unsigned char *vWork;
  unsigned char *extracted;
  unsigned char op[256];
  unsigned char scp;
  int fail;

  fail = 0;
  scp = 0x5a;
  b = 1U << h->h;
  waSz = sssMkWaSz(h->h, n);
  pfSz = sssMkPfSz(h->h, n);
  printf("\n== %s n=%u b=%u waSz=%u pfSz=%u ==\n",
   hashName, n, b, waSz, pfSz);

  /* allocate share buffers with distinct content per share.
   * content is arbitrary; the Merkle tree treats shares as opaque bytes. */
  shares = malloc(n * sizeof (*shares));
  cShares = malloc(n * sizeof (*cShares));
  proofs = malloc(n * sizeof (*proofs));
  work = malloc(waSz ? waSz : 1);
  vWork = malloc(sssMkVfSz(h->h));
  savedRoot = malloc(b);
  if (!shares || !cShares || !proofs || !work || !vWork || !savedRoot) {
    fprintf(stderr, "malloc\n");
    exit(1);
  }
  for (i = 0; i < n; ++i) {
    shares[i] = malloc(ShareLen);
    /* allocate at least one byte so the library's null-pointer guard
     * does not trip on the degenerate pfSz=0 case (n=1) */
    proofs[i] = malloc(pfSz ? pfSz : 1);
    if (!shares[i] || !proofs[i]) {
      fprintf(stderr, "malloc\n");
      exit(1);
    }
    for (j = 0; j < ShareLen; ++j)
      shares[i][j] = (unsigned char)((i * 37 + j) & 0xff);
    op[i] = (unsigned char)i;
    cShares[i] = shares[i];
  }

  /* build tree */
  root = sssMkHash(h, scp, op, cShares, ShareLen, n, work);
  if (!root) {
    printf("  sssMkHash: FAIL\n");
    fail = 1;
    goto cleanup;
  }
  memcpy(savedRoot, root, b);

  /* extract and verify every share */
  for (i = 0; i < n; ++i) {
    if (!sssMkProof(h, n, i, work, proofs[i])) {
      printf("  sssMkProof[%u]: FAIL\n", i);
      fail = 1;
      goto cleanup;
    }
    extracted = sssMkExtract(h, scp, op[i], cShares[i], ShareLen, i, n, proofs[i], vWork);
    if (!extracted || memcmp(extracted, savedRoot, b) != 0) {
      printf("  verify[%u]: FAIL\n", i);
      fail = 1;
      goto cleanup;
    }
  }
  printf("  verify all %u shares: PASS\n", n);

  /* negative: bit-flip corruption */
  shares[0][0] ^= 0xff;
  extracted = sssMkExtract(h, scp, op[0], cShares[0], ShareLen, 0, n, proofs[0], vWork);
  if (extracted && memcmp(extracted, savedRoot, b) == 0) {
    printf("  corruption rejection: FAIL (accepted corrupted share)\n");
    fail = 1;
  } else
    printf("  corruption rejection: PASS\n");
  shares[0][0] ^= 0xff;

  /* negative: wrong index (only meaningful when n > 1) */
  if (n > 1) {
    extracted = sssMkExtract(h, scp, op[0], cShares[0], ShareLen, 1, n, proofs[0], vWork);
    if (extracted && memcmp(extracted, savedRoot, b) == 0) {
      printf("  wrong-index rejection: FAIL\n");
      fail = 1;
    } else
      printf("  wrong-index rejection: PASS\n");
  }

  /* negative: wrong n (larger). the verifier thinks tree has n+1 shares;
   * the recomputed root must differ because n is bound at the root. */
  if (n < 256) {
    extracted = sssMkExtract(h, scp, op[0], cShares[0], ShareLen, 0, n + 1, proofs[0], vWork);
    if (extracted && memcmp(extracted, savedRoot, b) == 0) {
      printf("  wrong-n(+1) rejection: FAIL\n");
      fail = 1;
    } else
      printf("  wrong-n(+1) rejection: PASS\n");
  }

  /* negative: wrong n (smaller, same padded size). important case:
   * without n-binding, n=3 and n=4 would produce identical walks for i<3. */
  if (n > 1) {
    extracted = sssMkExtract(h, scp, op[0], cShares[0], ShareLen, 0, n - 1, proofs[0], vWork);
    if (extracted && memcmp(extracted, savedRoot, b) == 0) {
      printf("  wrong-n(-1) rejection: FAIL\n");
      fail = 1;
    } else
      printf("  wrong-n(-1) rejection: PASS\n");
  }

  /* negative: wrong ocp (relabel). same value and index, different code
   * point -- the leaf binds ocp, so the recomputed root must differ. */
  extracted = sssMkExtract(h, scp, (unsigned char)(op[0] ^ 0xff),
   cShares[0], ShareLen, 0, n, proofs[0], vWork);
  if (extracted && memcmp(extracted, savedRoot, b) == 0) {
    printf("  wrong-ocp rejection: FAIL\n");
    fail = 1;
  } else
    printf("  wrong-ocp rejection: PASS\n");

  /* negative: wrong scp. scp is bound at the root, so a different secret
   * code point must yield a different root. */
  extracted = sssMkExtract(h, (unsigned char)(scp ^ 0xff), op[0],
   cShares[0], ShareLen, 0, n, proofs[0], vWork);
  if (extracted && memcmp(extracted, savedRoot, b) == 0) {
    printf("  wrong-scp rejection: FAIL\n");
    fail = 1;
  } else
    printf("  wrong-scp rejection: PASS\n");

  /* null-argument guards */
  if (sssMkHash(0, scp, op, cShares, ShareLen, n, work)
   || sssMkHash(h, scp, 0, cShares, ShareLen, n, work)
   || sssMkHash(h, scp, op, 0, ShareLen, n, work)
   || sssMkHash(h, scp, op, cShares, 0, n, work)
   || sssMkHash(h, scp, op, cShares, ShareLen, 0, work)
   || sssMkHash(h, scp, op, cShares, ShareLen, 257, work)
   || sssMkHash(h, scp, op, cShares, ShareLen, n, 0)) {
    printf("  Hash null-arg guards: FAIL\n");
    fail = 1;
  }
  if (sssMkProof(0, n, 0, work, proofs[0])
   || sssMkProof(h, 0, 0, work, proofs[0])
   || sssMkProof(h, 257, 0, work, proofs[0])
   || sssMkProof(h, n, n, work, proofs[0])
   || sssMkProof(h, n, 0, 0, proofs[0])
   || sssMkProof(h, n, 0, work, 0)) {
    printf("  Proof null-arg guards: FAIL\n");
    fail = 1;
  }
  if (sssMkExtract(0, scp, op[0], shares[0], ShareLen, 0, n, proofs[0], vWork)
   || sssMkExtract(h, scp, op[0], 0, ShareLen, 0, n, proofs[0], vWork)
   || sssMkExtract(h, scp, op[0], shares[0], 0, 0, n, proofs[0], vWork)
   || sssMkExtract(h, scp, op[0], shares[0], ShareLen, n, n, proofs[0], vWork)
   || sssMkExtract(h, scp, op[0], shares[0], ShareLen, 0, 0, proofs[0], vWork)
   || sssMkExtract(h, scp, op[0], shares[0], ShareLen, 0, 257, proofs[0], vWork)
   || sssMkExtract(h, scp, op[0], shares[0], ShareLen, 0, n, 0, vWork)
   || sssMkExtract(h, scp, op[0], shares[0], ShareLen, 0, n, proofs[0], 0)) {
    printf("  Extract null-arg guards: FAIL\n");
    fail = 1;
  }
  if (!fail)
    printf("  argument guards: PASS\n");

cleanup:
  for (i = 0; i < n; ++i) {
    free(shares[i]);
    free(proofs[i]);
  }
  free(shares);
  free(cShares);
  free(proofs);
  free(work);
  free(vWork);
  free(savedRoot);
  return (fail);
}

int
main(
  void
){
  static const unsigned char Secret[] =
    "Hello Sam, this is a test of Merkle authenticated"
    " Shamir secret sharing."
    " The quick brown fox jumps over the lazy dog.";
  enum { M = 3, N = 4 };
  sssMkHsh_t Hrmd;
  sssMkHsh_t Hsha;
  unsigned int secretLen;
  unsigned int pfSz;
  unsigned int waSz;
  unsigned char ip[M];
  unsigned char op[N];
  unsigned char *iv[M];
  unsigned char *ov[N];
  const unsigned char *cov[N];
  unsigned char *mkWork;
  unsigned char *vfWork;
  unsigned char *root;
  unsigned char *proofBuf[N];
  unsigned int i;
  unsigned int j;
  int fail;
  FILE *f;
  unsigned int nTests[] = { 1, 2, 3, 5, 7, 8, 100, 255, 256 };

  fail = 0;
  secretLen = sizeof (Secret) - 1;

  /* rmd128 (2^4 = 16 bytes) */
  Hrmd.a = rmd128Allocate;
  Hrmd.i = (void(*)(void *))rmd128init;
  Hrmd.u = (void(*)(void *, const unsigned char *, unsigned int))rmd128update;
  Hrmd.f = (void(*)(void *, unsigned char *))rmd128final;
  Hrmd.d = free;
  Hrmd.h = 4;

  /* sha256 (2^5 = 32 bytes) */
  Hsha.a = sha256Allocate;
  Hsha.i = (void(*)(void *))sha256init;
  Hsha.u = (void(*)(void *, const unsigned char *, unsigned int))sha256update;
  Hsha.f = (void(*)(void *, unsigned char *))sha256final;
  Hsha.d = free;
  Hsha.h = 5;

  printf("Secret (%u bytes): %.*s\n", secretLen, (int)secretLen, Secret);

  /*
   * Test 1: narrative integration (SSS + Merkle, M=3, N=4, rmd128)
   */
  printf("\nTest 1: SSS+Merkle integration (M=%u N=%u, rmd128)\n",
   (unsigned)M, (unsigned)N);

  /* secret at point 0 */
  ip[0] = 0;
  iv[0] = malloc(secretLen);
  if (!iv[0]) {
    fprintf(stderr, "malloc\n");
    return (1);
  }
  memcpy(iv[0], Secret, secretLen);

  /* random data at point 1 from test/r1 */
  ip[1] = 1;
  iv[1] = malloc(secretLen);
  if (!iv[1]) {
    fprintf(stderr, "malloc\n");
    return (1);
  }
  f = fopen("test/r1", "rb");
  if (!f) {
    fprintf(stderr, "fopen test/r1\n");
    return (1);
  }
  if (fread(iv[1], 1, secretLen, f) != secretLen) {
    fprintf(stderr, "fread test/r1\n");
    fclose(f);
    return (1);
  }
  fclose(f);

  /* random data at point 2 from test/r2 */
  ip[2] = 2;
  iv[2] = malloc(secretLen);
  if (!iv[2]) {
    fprintf(stderr, "malloc\n");
    return (1);
  }
  f = fopen("test/r2", "rb");
  if (!f) {
    fprintf(stderr, "fopen test/r2\n");
    return (1);
  }
  if (fread(iv[2], 1, secretLen, f) != secretLen) {
    fprintf(stderr, "fread test/r2\n");
    fclose(f);
    return (1);
  }
  fclose(f);

  /* output shares at points 3, 4, 5, 6 */
  op[0] = 3;
  op[1] = 4;
  op[2] = 5;
  op[3] = 6;
  for (i = 0; i < N; ++i) {
    ov[i] = malloc(secretLen);
    if (!ov[i]) {
      fprintf(stderr, "malloc\n");
      return (1);
    }
    cov[i] = ov[i];
  }

  sss(ip, op, iv, ov, M, N, secretLen);

  for (i = 0; i < N; ++i) {
    printf("  share %u (point %u):", i, (unsigned)op[i]);
    for (j = 0; j < secretLen && j < 16; ++j)
      printf(" %02x", ov[i][j]);
    if (secretLen > 16)
      printf(" ...");
    printf("\n");
  }

  waSz = sssMkWaSz(Hrmd.h, N);
  pfSz = sssMkPfSz(Hrmd.h, N);
  mkWork = malloc(waSz);
  if (!mkWork) {
    fprintf(stderr, "malloc\n");
    return (1);
  }
  root = sssMkHash(&Hrmd, ip[0], op, cov, secretLen, N, mkWork);
  if (!root) {
    fprintf(stderr, "sssMkHash\n");
    return (1);
  }
  printf("  Root:");
  for (i = 0; i < (1U << Hrmd.h); ++i)
    printf(" %02x", root[i]);
  printf("\n");

  vfWork = malloc(sssMkVfSz(Hrmd.h));
  if (!vfWork) {
    fprintf(stderr, "malloc\n");
    return (1);
  }
  for (i = 0; i < N; ++i) {
    unsigned char *extracted;

    proofBuf[i] = malloc(pfSz);
    if (!proofBuf[i]) {
      fprintf(stderr, "malloc\n");
      return (1);
    }
    if (!sssMkProof(&Hrmd, N, i, mkWork, proofBuf[i])) {
      fprintf(stderr, "sssMkProof %u\n", i);
      return (1);
    }
    extracted = sssMkExtract(&Hrmd, ip[0], op[i], cov[i], secretLen, i, N,
     proofBuf[i], vfWork);
    if (!extracted
     || memcmp(extracted, root, 1U << Hrmd.h) != 0) {
      printf("  share %u verify: FAIL\n", i);
      fail = 1;
    } else
      printf("  share %u verify: PASS\n", i);
  }

  /* recover secret from shares 0, 2, 3 (at points 3, 5, 6) */
  {
    unsigned char rip[M];
    unsigned char rop[1];
    unsigned char *riv[M];
    unsigned char *rov[1];

    rip[0] = op[0]; riv[0] = ov[0];
    rip[1] = op[2]; riv[1] = ov[2];
    rip[2] = op[3]; riv[2] = ov[3];
    rop[0] = ip[0];
    rov[0] = malloc(secretLen);
    if (!rov[0]) {
      fprintf(stderr, "malloc\n");
      return (1);
    }

    sss(rip, rop, riv, rov, M, 1, secretLen);

    if (memcmp(rov[0], Secret, secretLen) == 0)
      printf("  recovered secret: PASS\n");
    else {
      printf("  recovered secret: FAIL\n");
      fail = 1;
    }

    free(rov[0]);
  }

  /* cleanup narrative test */
  for (i = 0; i < N; ++i)
    free(proofBuf[i]);
  free(vfWork);
  free(mkWork);
  for (i = 0; i < N; ++i)
    free(ov[i]);
  for (i = 0; i < M; ++i)
    free(iv[i]);

  /*
   * Test 2: parametric coverage (n edge cases, two hash sizes)
   */
  printf("\nTest 2: parametric coverage");
  for (i = 0; i < sizeof (nTests) / sizeof (nTests[0]); ++i) {
    if (parametricTest(&Hrmd, "rmd128", nTests[i]))
      fail = 1;
    if (parametricTest(&Hsha, "sha256", nTests[i]))
      fail = 1;
  }

  printf("\nAll tests completed%s.\n", fail ? " with FAILURES" : "");
  return (fail);
}
