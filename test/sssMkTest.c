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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sss.h"
#include "sssMk.h"
#include "rmd128.h"

static void *
hashAllocate(
  void
){
  return (malloc(rmd128tsize()));
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
  sssMkHsh_t Hsh;
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

  fail = 0;
  secretLen = sizeof (Secret) - 1;

  /* hash context: rmd128 (2^4 = 16 bytes) */
  Hsh.a = hashAllocate;
  Hsh.i = (void(*)(void *))rmd128init;
  Hsh.u = (void(*)(void *, const unsigned char *, unsigned int))rmd128update;
  Hsh.f = (void(*)(void *, unsigned char *))rmd128final;
  Hsh.d = free;
  Hsh.h = 4;

  printf("Secret (%u bytes): %.*s\n", secretLen, (int)secretLen, Secret);

  /*
   * Step 1: Create shares (M=3 threshold, N=4 shares)
   */
  printf("\nStep 1: Create shares (M=%u N=%u)\n", (unsigned)M, (unsigned)N);

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

  /*
   * Step 2: Build Merkle tree
   */
  printf("\nStep 2: Merkle tree (n=%u)\n", (unsigned)N);
  waSz = sssMkWaSz(Hsh.h, N);
  pfSz = sssMkPfSz(Hsh.h, N);
  printf("  Work area: %u bytes, proof size: %u bytes\n", waSz, pfSz);

  mkWork = malloc(waSz);
  if (!mkWork) {
    fprintf(stderr, "malloc\n");
    return (1);
  }
  root = sssMkHash(&Hsh, cov, secretLen, N, mkWork);
  if (!root) {
    fprintf(stderr, "sssMkHash\n");
    return (1);
  }
  printf("  Root:");
  for (i = 0; i < (1U << Hsh.h); ++i)
    printf(" %02x", root[i]);
  printf("\n");

  /*
   * Step 3: Extract proofs and verify all shares
   */
  printf("\nStep 3: Verify all shares\n");
  vfWork = malloc(sssMkVfSz(Hsh.h));
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
    if (!sssMkProof(&Hsh, N, i, mkWork, proofBuf[i])) {
      fprintf(stderr, "sssMkProof %u\n", i);
      return (1);
    }
    extracted = sssMkExtract(&Hsh, cov[i], secretLen, i, N,
     proofBuf[i], vfWork);
    if (!extracted
     || memcmp(extracted, root, 1U << Hsh.h) != 0) {
      printf("  share %u: FAIL\n", i);
      fail = 1;
    } else
      printf("  share %u: PASS\n", i);
  }

  /*
   * Step 4: Corruption detection
   */
  printf("\nStep 4: Corruption detection\n");
  {
    unsigned char *extracted;

    ov[0][0] ^= 0xff;
    extracted = sssMkExtract(&Hsh, cov[0], secretLen, 0, N,
     proofBuf[0], vfWork);
    if (!extracted
     || memcmp(extracted, root, 1U << Hsh.h) != 0)
      printf("  Corrupted share: FAIL (expected)\n");
    else {
      printf("  Corrupted share: PASS (unexpected!)\n");
      fail = 1;
    }
    ov[0][0] ^= 0xff; /* restore */

    extracted = sssMkExtract(&Hsh, cov[0], secretLen, 1, N,
     proofBuf[0], vfWork);
    if (!extracted
     || memcmp(extracted, root, 1U << Hsh.h) != 0)
      printf("  Wrong index: FAIL (expected)\n");
    else {
      printf("  Wrong index: PASS (unexpected!)\n");
      fail = 1;
    }
  }

  /*
   * Step 5: Recover secret from M shares (using shares 0, 2, 3)
   */
  printf("\nStep 5: Recover secret (using shares 0, 2, 3)\n");
  {
    unsigned char rip[M];
    unsigned char rop[1];
    unsigned char *riv[M];
    unsigned char *rov[1];

    /* verify received shares */
    for (i = 0; i < M; ++i) {
      unsigned char *extracted;
      unsigned int si;

      si = (i == 0) ? 0 : (i == 1) ? 2 : 3;
      extracted = sssMkExtract(&Hsh, cov[si], secretLen, si, N,
       proofBuf[si], vfWork);
      if (!extracted
       || memcmp(extracted, root, 1U << Hsh.h) != 0) {
        printf("  Verify share %u: FAIL\n", si);
        return (1);
      }
    }
    printf("  All received shares verified\n");

    /* shares 0, 2, 3 are at points 3, 5, 6 */
    rip[0] = op[0]; riv[0] = ov[0];
    rip[1] = op[2]; riv[1] = ov[2];
    rip[2] = op[3]; riv[2] = ov[3];
    rop[0] = ip[0]; /* secret point */
    rov[0] = malloc(secretLen);
    if (!rov[0]) {
      fprintf(stderr, "malloc\n");
      return (1);
    }

    sss(rip, rop, riv, rov, M, 1, secretLen);
    printf("  SSS recover: OK\n");

    if (memcmp(rov[0], Secret, secretLen) == 0)
      printf("  Secret match: PASS\n");
    else {
      printf("  Secret match: FAIL\n");
      fail = 1;
    }

    free(rov[0]);
  }

  /* cleanup */
  for (i = 0; i < N; ++i)
    free(proofBuf[i]);
  free(vfWork);
  free(mkWork);
  for (i = 0; i < N; ++i)
    free(ov[i]);
  for (i = 0; i < M; ++i)
    free(iv[i]);

  printf("\nAll tests completed%s.\n", fail ? " with FAILURES" : "");
  return (fail);
}
