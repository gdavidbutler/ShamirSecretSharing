/*
 * asynchronousByzantineAgreementProtocols - thrDsp SSS adapter test
 * Copyright (C) 2026 G. David Butler <gdb@dbSystems.com>
 *
 * This file is part of asynchronousByzantineAgreementProtocols
 *
 * asynchronousByzantineAgreementProtocols is free software: you can
 * redistribute it and/or modify it under the terms of the GNU Lesser General
 * Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * asynchronousByzantineAgreementProtocols is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "thrDsp.h"
#include "thrDspSss.h"
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

/* Deterministic pseudo-random for SSS input shares. Test-only;
 * production callers wire arc4random_buf or similar via cfg.randCtx.
 * The LCG state is the closure so the driver can reseed for
 * reproducibility checks. */
struct detRandCtx {
  unsigned long state;
};

static void
detRand(
  void *ctx
 ,unsigned char *buf
 ,unsigned int len
){
  struct detRandCtx *c;
  unsigned int i;

  c = (struct detRandCtx *)ctx;
  for (i = 0; i < len; ++i) {
    c->state = c->state * 1103515245UL + 12345UL;
    buf[i] = (unsigned char)(c->state >> 16);
  }
}

/* SSS point map: piece index i -> point i + 1, all in [1, 256). The
 * driver uses secretPoint = 0 (gap below) and secretPoint = 200 (gap
 * above); both are distinct from sharePt(i) for any i in [0, 255). */
static unsigned char
detSharePt(
  unsigned int i
){
  return ((unsigned char)(i + 1));
}

/* Honest-dealer roundtrip — see thrDspRsecTest.c for the predicate
 * tour. SSS-specific: re-seed RNG before re-encode determinism check. */
static int
runOne(
  const char *label
 ,const struct thrDsp *d
 ,struct detRandCtx *rng
 ,unsigned long rngSeed
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
){
  unsigned int k;
  unsigned int pieceSz;
  unsigned int proofSz;
  unsigned int rootSz;
  unsigned int encWa;
  unsigned int vfWa;
  unsigned int decWa;
  unsigned int derWa;
  unsigned int i;
  unsigned int j;
  unsigned int maxN;
  unsigned char *payload;
  unsigned char *recovered;
  unsigned char **pieces;
  unsigned char **proofs;
  unsigned char *root;
  unsigned char *root2;
  unsigned char *derRoot;
  unsigned char *derProof;
  unsigned char *encWork;
  unsigned char *vfWork;
  unsigned char *decWork;
  unsigned char *derWork;
  unsigned char *idx;
  const unsigned char **decPieces;
  int fail;

  fail = 0;
  maxN = d->vt->maxN(d);
  if (n > maxN) {
    printf("  %s n=%u t=%u L=%u: SKIP (exceeds maxN=%u)\n",
     label, n, t, payloadLen, maxN);
    return (0);
  }
  k = d->vt->threshold(n, t);
  if (!k || k > n) {
    printf("  %s n=%u t=%u L=%u: SKIP (k=%u invalid)\n",
     label, n, t, payloadLen, k);
    return (0);
  }
  pieceSz = d->vt->pieceSz(d, payloadLen, n, t);
  proofSz = d->vt->proofSz(d, n);
  rootSz = d->vt->rootSz(d);
  encWa = d->vt->encWaSz(d, n, t, payloadLen);
  vfWa = d->vt->vfWaSz(d);
  decWa = d->vt->decWaSz(d, n, t, payloadLen);
  derWa = d->vt->derivedRootWaSz(d, n, t, payloadLen);

  printf("  %s n=%u t=%u L=%u k=%u pieceSz=%u proofSz=%u rootSz=%u"
   " encWa=%u vfWa=%u decWa=%u derWa=%u\n",
   label, n, t, payloadLen, k, pieceSz, proofSz, rootSz,
   encWa, vfWa, decWa, derWa);

  payload = malloc(payloadLen);
  recovered = malloc(payloadLen);
  pieces = malloc(n * sizeof (*pieces));
  proofs = malloc(n * sizeof (*proofs));
  root = malloc(rootSz);
  root2 = malloc(rootSz);
  derRoot = malloc(rootSz);
  derProof = malloc(proofSz ? proofSz : 1);
  encWork = malloc(encWa ? encWa : 1);
  vfWork = malloc(vfWa ? vfWa : 1);
  decWork = malloc(decWa ? decWa : 1);
  derWork = malloc(derWa ? derWa : 1);
  idx = malloc(k);
  decPieces = malloc(k * sizeof (*decPieces));
  if (!payload || !recovered || !pieces || !proofs || !root || !root2
   || !derRoot || !derProof || !encWork || !vfWork || !decWork || !derWork
   || !idx || !decPieces) {
    fprintf(stderr, "    malloc\n");
    exit(1);
  }
  for (i = 0; i < n; ++i) {
    pieces[i] = malloc(pieceSz);
    proofs[i] = malloc(proofSz ? proofSz : 1);
    if (!pieces[i] || !proofs[i]) {
      fprintf(stderr, "    malloc\n");
      exit(1);
    }
  }
  for (i = 0; i < payloadLen; ++i)
    payload[i] = (unsigned char)((i * 131 + 7) & 0xff);

  if (rng)
    rng->state = rngSeed;
  if (d->vt->encode(d, payload, payloadLen, n, t,
   pieces, proofs, root, encWork)) {
    printf("    encode: FAIL\n");
    fail = 1;
    goto cleanup;
  }

  for (i = 0; i < n; ++i)
    if (d->vt->verify(d, i, n, t, payloadLen,
     pieces[i], proofs[i], root, vfWork)) {
      printf("    verify[%u]: FAIL\n", i);
      fail = 1;
      goto cleanup;
    }

  pieces[0][0] ^= 0xff;
  if (!d->vt->verify(d, 0, n, t, payloadLen,
   pieces[0], proofs[0], root, vfWork)) {
    printf("    corruption rejection: FAIL (accepted)\n");
    fail = 1;
  }
  pieces[0][0] ^= 0xff;

  if (n > 1) {
    if (!d->vt->verify(d, 1, n, t, payloadLen,
     pieces[0], proofs[0], root, vfWork)) {
      printf("    wrong-index rejection: FAIL\n");
      fail = 1;
    }
  }

  if (n < maxN) {
    if (!d->vt->verify(d, 0, n + 1, t, payloadLen,
     pieces[0], proofs[0], root, vfWork)) {
      printf("    wrong-n(+1) rejection: FAIL\n");
      fail = 1;
    }
  }

  if (n > 1) {
    if (!d->vt->verify(d, 0, n - 1, t, payloadLen,
     pieces[0], proofs[0], root, vfWork)) {
      printf("    wrong-n(-1) rejection: FAIL\n");
      fail = 1;
    }
  }

  for (j = 0; j < k; ++j) {
    idx[j] = (unsigned char)j;
    decPieces[j] = pieces[j];
  }
  if (d->vt->decode(d, n, t, payloadLen, idx, decPieces, recovered, decWork)) {
    printf("    decode(first k): FAIL\n");
    fail = 1;
    goto cleanup;
  }
  if (memcmp(recovered, payload, payloadLen) != 0) {
    printf("    decode(first k) roundtrip: FAIL\n");
    fail = 1;
  }

  if (n > k) {
    for (j = 0; j < k; ++j) {
      idx[j] = (unsigned char)(n - k + j);
      decPieces[j] = pieces[n - k + j];
    }
    memset(recovered, 0xa5, payloadLen);
    if (d->vt->decode(d, n, t, payloadLen, idx, decPieces, recovered, decWork)) {
      printf("    decode(last k): FAIL\n");
      fail = 1;
    } else if (memcmp(recovered, payload, payloadLen) != 0) {
      printf("    decode(last k) roundtrip: FAIL\n");
      fail = 1;
    }
  }

  /* derivedRoot from first-k subset -> matches original root */
  for (j = 0; j < k; ++j) {
    idx[j] = (unsigned char)j;
    decPieces[j] = pieces[j];
  }
  if (d->vt->derivedRoot(d, n, t, payloadLen, idx, decPieces,
   derRoot, 0, 0, 0, derWork)) {
    printf("    derivedRoot(first k): FAIL\n");
    fail = 1;
  } else if (memcmp(derRoot, root, rootSz) != 0) {
    printf("    derivedRoot(first k) root mismatch: FAIL\n");
    fail = 1;
  }

  if (n > k) {
    for (j = 0; j < k; ++j) {
      idx[j] = (unsigned char)(n - k + j);
      decPieces[j] = pieces[n - k + j];
    }
    if (d->vt->derivedRoot(d, n, t, payloadLen, idx, decPieces,
     derRoot, 0, 0, 0, derWork)) {
      printf("    derivedRoot(last k): FAIL\n");
      fail = 1;
    } else if (memcmp(derRoot, root, rootSz) != 0) {
      printf("    derivedRoot(last k) root mismatch: FAIL\n");
      fail = 1;
    }
  }

  /* derivedRoot with per-piece proof+piece extraction: AVID-H
   * READY-broadcast path. From the first-k subset, extract proof
   * AND piece for piece index n-1 (reconstructed by interpolation,
   * not passed in). The re-derived (piece, proof) pair must verify
   * against the re-derived root, the piece must match the original,
   * and a one-byte corruption of the proof must be rejected. */
  if (n > k) {
    unsigned char *derPiece;
    derPiece = malloc(pieceSz);
    if (!derPiece) {
      fprintf(stderr, "    derPiece malloc\n");
      exit(1);
    }
    for (j = 0; j < k; ++j) {
      idx[j] = (unsigned char)j;
      decPieces[j] = pieces[j];
    }
    if (d->vt->derivedRoot(d, n, t, payloadLen, idx, decPieces,
     derRoot, n - 1, derProof, derPiece, derWork)) {
      printf("    derivedRoot(first k, +proof+piece[n-1]): FAIL\n");
      fail = 1;
    } else {
      if (memcmp(derRoot, root, rootSz) != 0) {
        printf("    derivedRoot(+proof+piece) root mismatch: FAIL\n");
        fail = 1;
      }
      if (memcmp(derPiece, pieces[n - 1], pieceSz) != 0) {
        printf("    derivedRoot piece[n-1] mismatch: FAIL\n");
        fail = 1;
      }
      if (d->vt->verify(d, n - 1, n, t, payloadLen,
       derPiece, derProof, derRoot, vfWork)) {
        printf("    verify(n-1, derPiece, derProof): FAIL\n");
        fail = 1;
      }
      derProof[0] ^= 0xff;
      if (!d->vt->verify(d, n - 1, n, t, payloadLen,
       pieces[n - 1], derProof, derRoot, vfWork)) {
        printf("    derProof corruption rejection: FAIL (accepted)\n");
        fail = 1;
      }
      derProof[0] ^= 0xff;
    }
    free(derPiece);
  }

  /* re-encode determinism: same RNG seed -> same root */
  if (rng)
    rng->state = rngSeed;
  if (d->vt->encode(d, payload, payloadLen, n, t,
   pieces, proofs, root2, encWork)) {
    printf("    re-encode: FAIL\n");
    fail = 1;
  } else if (memcmp(root, root2, rootSz) != 0) {
    printf("    re-encode root mismatch: FAIL\n");
    fail = 1;
  }

cleanup:
  for (i = 0; i < n; ++i) {
    free(pieces[i]);
    free(proofs[i]);
  }
  free(pieces);
  free(proofs);
  free(payload);
  free(recovered);
  free(root);
  free(root2);
  free(derRoot);
  free(derProof);
  free(encWork);
  free(vfWork);
  free(decWork);
  free(derWork);
  free(idx);
  free(decPieces);
  return (fail);
}

/* Byzantine-dealer splice — see thrDspRsecTest.c for the rationale.
 * SSS-specific: each independent encode draws from the RNG so the two
 * payloads have polynomials seeded differently. */
static int
runFrankenstein(
  const char *label
 ,const struct thrDsp *d
 ,const sssMkHsh_t *h
 ,struct detRandCtx *rng
 ,unsigned long rngSeed
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
){
  unsigned int k;
  unsigned int pieceSz;
  unsigned int proofSz;
  unsigned int rootSz;
  unsigned int encWa;
  unsigned int derWa;
  unsigned int treeWa;
  unsigned int i;
  unsigned int j;
  unsigned char *payloadA;
  unsigned char *payloadB;
  unsigned char **piecesA;
  unsigned char **piecesB;
  unsigned char **proofsTmp;
  const unsigned char **frankenLeaves;
  unsigned char *rootA;
  unsigned char *rootB;
  unsigned char *frankenRoot;
  unsigned char *derRoot;
  unsigned char *encWork;
  unsigned char *derWork;
  unsigned char *mkWork;
  unsigned char *idx;
  const unsigned char **decPieces;
  unsigned char *fr;
  int fail;

  fail = 0;
  k = d->vt->threshold(n, t);
  if (!k || n <= k)
    return (0);
  pieceSz = d->vt->pieceSz(d, payloadLen, n, t);
  proofSz = d->vt->proofSz(d, n);
  rootSz = d->vt->rootSz(d);
  encWa = d->vt->encWaSz(d, n, t, payloadLen);
  derWa = d->vt->derivedRootWaSz(d, n, t, payloadLen);
  treeWa = sssMkWaSz(h->h, n);

  printf("  %s frankenstein n=%u t=%u L=%u k=%u\n",
   label, n, t, payloadLen, k);

  payloadA = malloc(payloadLen);
  payloadB = malloc(payloadLen);
  piecesA = malloc(n * sizeof (*piecesA));
  piecesB = malloc(n * sizeof (*piecesB));
  proofsTmp = malloc(n * sizeof (*proofsTmp));
  frankenLeaves = malloc(n * sizeof (*frankenLeaves));
  rootA = malloc(rootSz);
  rootB = malloc(rootSz);
  frankenRoot = malloc(rootSz);
  derRoot = malloc(rootSz);
  encWork = malloc(encWa ? encWa : 1);
  derWork = malloc(derWa ? derWa : 1);
  mkWork = malloc(treeWa ? treeWa : 1);
  idx = malloc(k);
  decPieces = malloc(k * sizeof (*decPieces));
  for (i = 0; i < n; ++i) {
    piecesA[i] = malloc(pieceSz);
    piecesB[i] = malloc(pieceSz);
    proofsTmp[i] = malloc(proofSz ? proofSz : 1);
  }
  for (i = 0; i < payloadLen; ++i) {
    payloadA[i] = (unsigned char)((i * 131 + 7) & 0xff);
    payloadB[i] = (unsigned char)((i * 251 + 19) & 0xff);
  }

  if (rng) rng->state = rngSeed;
  if (d->vt->encode(d, payloadA, payloadLen, n, t,
   piecesA, proofsTmp, rootA, encWork)) {
    printf("    encode(A): FAIL\n"); fail = 1; goto cleanup;
  }
  if (rng) rng->state = rngSeed + 1;
  if (d->vt->encode(d, payloadB, payloadLen, n, t,
   piecesB, proofsTmp, rootB, encWork)) {
    printf("    encode(B): FAIL\n"); fail = 1; goto cleanup;
  }

  for (i = 0; i < k; ++i)
    frankenLeaves[i] = piecesA[i];
  for (i = k; i < n; ++i)
    frankenLeaves[i] = piecesB[i];

  fr = sssMkHash(h, frankenLeaves, pieceSz, n, mkWork);
  if (!fr) {
    printf("    franken Merkle hash: FAIL\n");
    fail = 1; goto cleanup;
  }
  memcpy(frankenRoot, fr, rootSz);

  for (j = 0; j < k; ++j) {
    idx[j] = (unsigned char)j;
    decPieces[j] = frankenLeaves[j];
  }
  if (d->vt->derivedRoot(d, n, t, payloadLen, idx, decPieces,
   derRoot, 0, 0, 0, derWork)) {
    printf("    derivedRoot(franken first k): FAIL\n");
    fail = 1; goto cleanup;
  }
  if (memcmp(derRoot, rootA, rootSz) != 0) {
    printf("    franken first-k derivedRoot != rootA: FAIL\n");
    fail = 1;
  }
  if (memcmp(derRoot, frankenRoot, rootSz) == 0) {
    printf("    franken first-k derivedRoot == frankenRoot (should reject): FAIL\n");
    fail = 1;
  }
  if (!fail)
    printf("    Byzantine-dealer rejection: PASS\n");

cleanup:
  for (i = 0; i < n; ++i) {
    free(piecesA[i]);
    free(piecesB[i]);
    free(proofsTmp[i]);
  }
  free(piecesA);
  free(piecesB);
  free(proofsTmp);
  free(frankenLeaves);
  free(payloadA);
  free(payloadB);
  free(rootA);
  free(rootB);
  free(frankenRoot);
  free(derRoot);
  free(encWork);
  free(derWork);
  free(mkWork);
  free(idx);
  free(decPieces);
  return (fail);
}

static int
runDefensiveNulls(
  const sssMkHsh_t *h
){
  struct thrDspSssCfg cfg;
  struct thrDsp d;
  int fail;

  fail = 0;
  cfg.h = h;
  cfg.sharePt = detSharePt;
  cfg.randBytes = 0;
  cfg.randCtx = 0;
  cfg.secretPoint = 0;
  if (!thrDspSssInit(0, &cfg)) {
    printf("  thrDspSssInit(null d): FAIL\n"); fail = 1;
  }
  if (!thrDspSssInit(&d, 0)) {
    printf("  thrDspSssInit(null cfg): FAIL\n"); fail = 1;
  }
  cfg.sharePt = 0;
  if (!thrDspSssInit(&d, &cfg)) {
    printf("  thrDspSssInit(null sharePt): FAIL\n"); fail = 1;
  }
  cfg.h = 0;
  cfg.sharePt = detSharePt;
  if (!thrDspSssInit(&d, &cfg)) {
    printf("  thrDspSssInit(null h): FAIL\n"); fail = 1;
  }
  thrDspSssFini(0);
  if (!fail)
    printf("  defensive-null guards: PASS\n");
  return (fail);
}

int
main(
  void
){
  sssMkHsh_t Hrmd;
  sssMkHsh_t Hsha;
  struct thrDspSssCfg cfgRmd;
  struct thrDspSssCfg cfgSha;
  struct thrDsp dRmd;
  struct thrDsp dSha;
  struct detRandCtx rng;
  unsigned long Seed = 0xC0DE1234UL;
  unsigned int nList[] = { 4, 7, 16, 64 };
  unsigned int tList[] = { 1, 2 };
  unsigned int lList[] = { 1, 17, 64, 1000 };
  unsigned int i;
  unsigned int j;
  unsigned int l;
  int fail;

  fail = 0;

  Hrmd.a = rmd128Allocate;
  Hrmd.i = (void(*)(void *))rmd128init;
  Hrmd.u = (void(*)(void *, const unsigned char *, unsigned int))rmd128update;
  Hrmd.f = (void(*)(void *, unsigned char *))rmd128final;
  Hrmd.d = free;
  Hrmd.h = 4;

  Hsha.a = sha256Allocate;
  Hsha.i = (void(*)(void *))sha256init;
  Hsha.u = (void(*)(void *, const unsigned char *, unsigned int))sha256update;
  Hsha.f = (void(*)(void *, unsigned char *))sha256final;
  Hsha.d = free;
  Hsha.h = 5;

  /* rmd128 / secretPoint = 0 */
  cfgRmd.h = &Hrmd;
  cfgRmd.secretPoint = 0;
  cfgRmd.sharePt = detSharePt;
  cfgRmd.randBytes = detRand;
  cfgRmd.randCtx = &rng;

  /* sha256 / secretPoint = 200 (non-zero gap-above) */
  cfgSha.h = &Hsha;
  cfgSha.secretPoint = 200;
  cfgSha.sharePt = detSharePt;
  cfgSha.randBytes = detRand;
  cfgSha.randCtx = &rng;

  if (thrDspSssInit(&dRmd, &cfgRmd) || thrDspSssInit(&dSha, &cfgSha)) {
    fprintf(stderr, "thrDspSssInit\n");
    return (1);
  }

  printf("== thrDspSss defensive null guards ==\n");
  if (runDefensiveNulls(&Hrmd))
    fail = 1;

  printf("\n== thrDspSss roundtrip (rmd128, sp=0) ==\n");
  for (i = 0; i < sizeof (nList) / sizeof (nList[0]); ++i)
    for (j = 0; j < sizeof (tList) / sizeof (tList[0]); ++j)
      for (l = 0; l < sizeof (lList) / sizeof (lList[0]); ++l)
        if (runOne("sss/rmd ", &dRmd, &rng, Seed,
         nList[i], tList[j], lList[l]))
          fail = 1;

  printf("\n== thrDspSss roundtrip (sha256, sp=200) ==\n");
  if (runOne("sss/sha ", &dSha, &rng, Seed, 16, 2, 64))
    fail = 1;
  if (runOne("sss/sha ", &dSha, &rng, Seed, 7, 1, 1000))
    fail = 1;

  printf("\n== thrDspSss edges ==\n");
  if (runOne("sss/rmd ", &dRmd, &rng, Seed, 255, 8, 128))
    fail = 1;
  if (runOne("sss/rmd ", &dRmd, &rng, Seed, 1, 0, 32))
    fail = 1;

  printf("\n== thrDspSss Byzantine-dealer (Frankenstein) ==\n");
  if (runFrankenstein("sss/rmd ", &dRmd, &Hrmd, &rng, Seed, 7, 2, 64))
    fail = 1;
  if (runFrankenstein("sss/sha ", &dSha, &Hsha, &rng, Seed, 16, 5, 100))
    fail = 1;

  thrDspSssFini(&dRmd);
  thrDspSssFini(&dSha);

  printf("\nAll tests completed%s.\n", fail ? " with FAILURES" : "");
  return (fail);
}
