/*
 * asynchronousByzantineAgreementProtocols - thrDsp Shamir adapter
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

#include <string.h>
#include "thrDspSss.h"
#include "sss.h"
#include "sssMk.h"

#define CFG(d) ((const struct thrDspSssCfg *)((d)->opaque))

static unsigned int
sMaxN(
  const struct thrDsp *d
){
  (void)d;
  return (255);
}

static unsigned int
sThreshold(
  unsigned int n
 ,unsigned int t
){
  if (n < 1 || n > 255 || t >= n)
    return (0);
  return (t + 1);
}

static unsigned int
sPieceSz(
  const struct thrDsp *d
 ,unsigned int payloadLen
 ,unsigned int n
 ,unsigned int t
){
  (void)d;
  if (!sThreshold(n, t) || !payloadLen)
    return (0);
  return (payloadLen);
}

static unsigned int
sRootSz(
  const struct thrDsp *d
){
  return (1U << CFG(d)->h->h);
}

static unsigned int
sProofSz(
  const struct thrDsp *d
 ,unsigned int n
){
  return (sssMkPfSz(CFG(d)->h->h, n));
}

static unsigned int
sEncWaSz(
  const struct thrDsp *d
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
){
  unsigned int m;
  unsigned int nOut;

  if (!sThreshold(n, t) || !payloadLen)
    return (0);
  m = t + 1;
  nOut = n - t;
  /* aligned-first layout:
   *   iv[m], ov[nOut], leaves[n]      (pointers, aligned)
   *   ip[m], op[nOut], secScratch[L]  (bytes)
   *   treeWa                          (bytes) */
  return ((m + nOut + n) * sizeof (unsigned char *)
        + m + nOut + payloadLen
        + sssMkWaSz(CFG(d)->h->h, n));
}

static unsigned int
sVfWaSz(
  const struct thrDsp *d
){
  return (sssMkVfSz(CFG(d)->h->h));
}

static unsigned int
sDecWaSz(
  const struct thrDsp *d
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
){
  unsigned int m;

  (void)d;
  if (!sThreshold(n, t) || !payloadLen)
    return (0);
  m = t + 1;
  /* aligned-first layout: iv[m], ov[1] (pointers); ip[m], op[1] (bytes) */
  return ((m + 1) * sizeof (unsigned char *) + m + 1);
}

static unsigned int
sDerivedRootWaSz(
  const struct thrDsp *d
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
){
  unsigned int m;
  unsigned int nMiss;

  if (!sThreshold(n, t) || !payloadLen)
    return (0);
  m = t + 1;
  nMiss = n - m;
  /* iv[m], ov[nMiss], leaves[n] (pointers, aligned)
   * + ip[m], op[nMiss] (bytes)
   * + scratch[n*payloadLen] (re-derived pieces in piece-index order)
   * + Merkle tree work area */
  return ((m + nMiss + n) * sizeof (unsigned char *)
        + m + nMiss
        + n * payloadLen
        + sssMkWaSz(CFG(d)->h->h, n));
}

static int
sEncode(
  const struct thrDsp *d
 ,const unsigned char *payload
 ,unsigned int payloadLen
 ,unsigned int n
 ,unsigned int t
 ,unsigned char *const *pieces
 ,unsigned char *const *proofs
 ,unsigned char *root
 ,unsigned char *work
){
  unsigned int m;
  unsigned int nOut;
  unsigned int i;
  unsigned char **iv;
  unsigned char **ov;
  const unsigned char **leaves;
  unsigned char *ip;
  unsigned char *op;
  unsigned char *secScratch;
  unsigned char *treeWa;
  unsigned char *r;

  if (!d || !payload || !payloadLen || !pieces || !proofs || !root || !work)
    return (-1);
  if (!sThreshold(n, t))
    return (-1);
  m = t + 1;
  nOut = n - t;
  if (t > 0 && !CFG(d)->randBytes)
    return (-1);

  /* pointer arrays first (aligned from work base), then byte arrays */
  iv = (unsigned char **)work;
  ov = iv + m;
  leaves = (const unsigned char **)(ov + nOut);
  ip = (unsigned char *)(leaves + n);
  op = ip + m;
  secScratch = op + nOut;
  treeWa = secScratch + payloadLen;

  /* iv[0] = secret (payload copy); ip[0] = secret point */
  memcpy(secScratch, payload, payloadLen);
  iv[0] = secScratch;
  ip[0] = CFG(d)->secretPoint;

  /* iv[1..M-1] = pieces[0..t-1], filled from cfg.randBytes;
   * ip[1..M-1] = sharePt(0..t-1). Pieces are independently allocated,
   * so one randBytes call per buffer. */
  for (i = 0; i < t; ++i) {
    iv[1 + i] = pieces[i];
    ip[1 + i] = CFG(d)->sharePt(i);
    CFG(d)->randBytes(CFG(d)->randCtx, pieces[i], payloadLen);
  }

  /* ov[0..N-1] = pieces[t..n-1]; op[0..N-1] = sharePt(t..n-1) */
  for (i = 0; i < nOut; ++i) {
    ov[i] = pieces[t + i];
    op[i] = CFG(d)->sharePt(t + i);
  }

  sss(ip, op, iv, ov, m, nOut, payloadLen);

  /* Merkle tree over all n pieces in piece-index order */
  for (i = 0; i < n; ++i)
    leaves[i] = pieces[i];
  r = sssMkHash(CFG(d)->h, leaves, payloadLen, n, treeWa);
  if (!r)
    return (-1);
  memcpy(root, r, 1U << CFG(d)->h->h);

  for (i = 0; i < n; ++i)
    if (!sssMkProof(CFG(d)->h, n, i, treeWa, proofs[i]))
      return (-1);
  return (0);
}

static int
sVerify(
  const struct thrDsp *d
 ,unsigned int i
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
 ,const unsigned char *piece
 ,const unsigned char *proof
 ,const unsigned char *root
 ,unsigned char *work
){
  unsigned char *r;

  (void)t;
  if (!d || !piece || !proof || !root || !work || !payloadLen)
    return (-1);
  r = sssMkExtract(CFG(d)->h, piece, payloadLen, i, n, proof, work);
  if (!r)
    return (-1);
  if (memcmp(r, root, 1U << CFG(d)->h->h) != 0)
    return (-1);
  return (0);
}

static int
sDecode(
  const struct thrDsp *d
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
 ,const unsigned char *indices
 ,const unsigned char *const *pieces
 ,unsigned char *payload
 ,unsigned char *work
){
  unsigned int m;
  unsigned int j;
  unsigned char **iv;
  unsigned char **ov;
  unsigned char *ip;
  unsigned char *op;

  if (!d || !indices || !pieces || !payload || !work || !payloadLen)
    return (-1);
  if (!sThreshold(n, t))
    return (-1);
  m = t + 1;

  /* pointer arrays first (aligned), then byte arrays */
  iv = (unsigned char **)work;
  ov = iv + m;
  ip = (unsigned char *)(ov + 1);
  op = ip + m;

  for (j = 0; j < m; ++j) {
    if (indices[j] >= n)
      return (-1);
    /* sss does not modify iv[] contents; const cast reflects API, not
     * behaviour. */
    iv[j] = (unsigned char *)pieces[j];
    ip[j] = CFG(d)->sharePt(indices[j]);
  }
  ov[0] = payload;
  op[0] = CFG(d)->secretPoint;

  sss(ip, op, iv, ov, m, 1, payloadLen);
  return (0);
}

static int
sDerivedRoot(
  const struct thrDsp *d
 ,unsigned int n
 ,unsigned int t
 ,unsigned int payloadLen
 ,const unsigned char *indices
 ,const unsigned char *const *pieces
 ,unsigned char *root
 ,unsigned int idxOut
 ,unsigned char *proof
 ,unsigned char *piece
 ,unsigned char *work
){
  unsigned int m;
  unsigned int nMiss;
  unsigned int i;
  unsigned int j;
  unsigned int oi;
  unsigned int known;
  unsigned char **iv;
  unsigned char **ov;
  const unsigned char **leaves;
  unsigned char *ip;
  unsigned char *op;
  unsigned char *scratch;
  unsigned char *treeWa;
  unsigned char *r;

  if (!d || !indices || !pieces || !root || !work)
    return (-1);
  if ((proof || piece) && idxOut >= n)
    return (-1);
  if (!sThreshold(n, t) || !payloadLen)
    return (-1);
  m = t + 1;
  nMiss = n - m;

  /* pointer arrays first (aligned), then byte arrays */
  iv = (unsigned char **)work;
  ov = iv + m;
  leaves = (const unsigned char **)(ov + nMiss);
  ip = (unsigned char *)(leaves + n);
  op = ip + m;
  scratch = op + nMiss;
  treeWa = scratch + n * payloadLen;

  /* copy known pieces into their piece-index slots in scratch and
   * stage them as sss() inputs */
  for (j = 0; j < m; ++j) {
    if (indices[j] >= n)
      return (-1);
    memcpy(scratch + indices[j] * payloadLen, pieces[j], payloadLen);
    iv[j] = scratch + indices[j] * payloadLen;
    ip[j] = CFG(d)->sharePt(indices[j]);
  }

  /* enumerate missing positions; stage them as sss() outputs to
   * interpolate-and-evaluate at sharePt(i) for each i not in indices */
  oi = 0;
  for (i = 0; i < n; ++i) {
    known = 0;
    for (j = 0; j < m; ++j)
      if (indices[j] == i) {
        known = 1;
        break;
      }
    if (!known) {
      op[oi] = CFG(d)->sharePt(i);
      ov[oi] = scratch + i * payloadLen;
      ++oi;
    }
  }
  if (nMiss)
    sss(ip, op, iv, ov, m, nMiss, payloadLen);

  /* Merkle root over all n re-derived shares in piece-index order */
  for (i = 0; i < n; ++i)
    leaves[i] = scratch + i * payloadLen;
  r = sssMkHash(CFG(d)->h, leaves, payloadLen, n, treeWa);
  if (!r)
    return (-1);
  memcpy(root, r, 1U << CFG(d)->h->h);
  if (proof && !sssMkProof(CFG(d)->h, n, idxOut, treeWa, proof))
    return (-1);
  if (piece)
    memcpy(piece, scratch + (unsigned long)idxOut * payloadLen, payloadLen);
  return (0);
}

static const struct thrDspVt Vt = {
  sMaxN
 ,sThreshold
 ,sPieceSz
 ,sRootSz
 ,sProofSz
 ,sEncWaSz
 ,sVfWaSz
 ,sDecWaSz
 ,sDerivedRootWaSz
 ,sEncode
 ,sVerify
 ,sDecode
 ,sDerivedRoot
};

int
thrDspSssInit(
  struct thrDsp *d
 ,const struct thrDspSssCfg *cfg
){
  if (!d || !cfg || !cfg->h || !cfg->sharePt)
    return (-1);
  d->vt = &Vt;
  d->opaque = cfg;
  return (0);
}

void
thrDspSssFini(
  struct thrDsp *d
){
  if (!d)
    return;
  d->vt = 0;
  d->opaque = 0;
}
