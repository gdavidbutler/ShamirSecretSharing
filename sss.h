/*
 * ShamirSecretSharing - A C language implementation of Shamir's secret sharing algorithm
 * Copyright (C) 2015-2023 G. David Butler <gdb@dbSystems.com>
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

#ifndef __SSS_H__
#define __SSS_H__

/* all buffers of values are the same length */
/* to create N values with a M value threshold of some reference value */
/*   input point 0 is the reference value */
/*   input point(s) 1 to 255 (M - 1) (cryptographically random) values */
/*   output point(s) 1 to 255 (N) values */
/* to recover the reference value from M values */
/*   input point(s) 1 to 255 (M) values */
/*   output point 0 is the recovered reference value */
void
sss(
  unsigned char *ip /* input points */
 ,unsigned char *op /* output points */
 ,unsigned char **iv /* input value buffers */
 ,unsigned char **ov /* output value buffers */
 ,unsigned int in /* number of ip and iv */
 ,unsigned int on /* number of op and ov */
 ,unsigned int ln /* length of each value buffer */
);

#endif /* __SSS_H__ */
