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

#ifndef THRDSPSSS_H
#define THRDSPSSS_H

#include "thrDsp.h"
#include "sssMk.h"

/*
 * Shamir Secret Sharing adapter for thrDsp.
 *
 * Each piece is one share (one GF(2^8) polynomial evaluation) of length
 * payloadLen. Threshold M = t + 1 shares reconstruct the payload by
 * Lagrange interpolation at cfg.secretPoint.
 *
 * Piece counting at n = 255:
 *   GF(2^8) has 256 points; one is cfg.secretPoint, leaving 255 share
 *   positions. The M-1 = t random "input" points sss() needs to fix the
 *   polynomial are themselves valid shares, so the adapter uses
 *   piece-indices [0, t) as input shares (filled from cfg.randBytes) and
 *   piece-indices [t, n) as output shares (sss() evaluates). All n
 *   pieces are first-class distributable shares.
 *
 * Caller-supplied closures via cfg:
 *
 *   h           - sssMk hash vtable
 *   secretPoint - GF(2^8) point at which the secret value lives.
 *                 Caller picks (e.g. 0, or random per epoch).
 *   sharePt(i)  - returns the GF(2^8) point for piece index i in
 *                 [0, maxN). Called by both encode and decode, so the
 *                 mapping must be a pure function (same i -> same point
 *                 for the lifetime of this struct thrDsp). Precondition:
 *                 sharePt(i) is distinct from secretPoint and distinct
 *                 from sharePt(j) for j != i. Adapter does not enforce
 *                 (cost is a 256-bit bitmap per encode for no operational
 *                 benefit — caller's map is typically static).
 *   randBytes(ctx, buf, len) - fills buf with len cryptographically
 *                 random bytes. randCtx is passed through as ctx.
 *                 Called t times per encode, each with len = payloadLen,
 *                 to populate the t input-share values. May be 0 if the
 *                 caller never uses t > 0; encode returns -1 if called
 *                 with t > 0 and randBytes == 0.
 *   randCtx     - opaque closure context passed to randBytes; the cfg
 *                 owns its lifetime.
 *
 * Caller-owned cfg outlives the struct thrDsp. randBytes must be
 * thread-safe to the extent the caller calls encode concurrently.
 *
 * Constraints:
 *   1 <= n <= 255, 0 <= t <= n - 1, payloadLen >= 1.
 */

struct thrDspSssCfg {
  const sssMkHsh_t *h;
  unsigned char (*sharePt)(unsigned int i);
  void (*randBytes)(void *ctx, unsigned char *buf, unsigned int len);
  void *randCtx;
  unsigned char secretPoint;
};

int
thrDspSssInit(
  struct thrDsp *d
 ,const struct thrDspSssCfg *cfg
);

void
thrDspSssFini(
  struct thrDsp *d
);

#endif /* THRDSPSSS_H */
