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

/* David Madore's original comments follow: (Note: the Makefile creates "main" not "shsecret") */

/* shsecret.c - Secret sharing algorithm */
/* Written by David Madore */
/* 2000/06/19 - Public Domain */
/* http://www.madore.org/~david/programs/#prog_shsecret */
/* ftp://ftp.madore.org/pub/madore/misc/shsecret.c */

/* This program implements a secret sharing algorithm.  In other
 * words, given a file (secret), it can produce N files of the same
 * size ("shares") such that knowing any M shares among N will be
 * sufficient to recover the secret (using this very program again)
 * whereas knowing less than M shares will yield _absolutely no
 * information_ on the secret, even with infinite computing power.
 * This program does both the sharing and the unsharing (it actually
 * does a little more than that).  N can be anywhere up to 255.  M can
 * be anywhere up to N. */

/* Features:
 * + Small is beautiful.
 * + Efficient (for small MN).
 * + No bignum arithmetic (only eight-bit calculations).
 * + Completely portable (only assumes input chars are eight-bit).
 * + No dynamic memory allocation whatsoever (roughly 70k static).
 * + Completely brain-dead command line syntax. */

/* How to use:
 * To share a secret:
   shsecret -secret.txt 1-/dev/urandom 2-/dev/urandom [...] \
      1+share1.dat 2+share2.dat 3+share3.dat [...]
   where the number of '-' command line arguments is M-1 and where the
   number of '+' command line arguments is N.
     If your system has no /dev/urandom-like random number generator,
   then write (cryptographically strong) random data in share1.dat,
   share2.dat and so on (M-1 of them), each one being the same size
   as secret.txt (at least) and run:
   shsecret -secret.txt 1-share1.dat 2-share2.dat [...] \
      M+shareM.dat [...]
   (that is, use a '-' for the first M-1 and a '+' for the following
   ones).  Then share1.dat through shareN.dat are the N shares.
 * To unshare a secret:
   shsecret 1-share1.dat 3-share3.dat 4-share4.dat [...] +secret.txt
   Enough shares must be given (i.e. at least M), but which are given
   is unimportant. */

/* Detailed instructions:
 * Syntax is "shsecret [point][+-][file] [...]"
 * Where [point] is an integer between 0 and 255 (if missing, counted
 * as 0; [+-] is either '+' for an output file or '-' for an input
 * file; and [file] is a file name.
 * This computes the so-called "Lagrange interpolating polynomial" on
 * the input files through the given input points and outputs its
 * values at the given output points in the given output files.  The
 * Lagrange interpolating polynomial, if defined by M input points, is
 * completely determined by its value at _any_ M points.
 * In particular, if shsecret is run with secret.txt as input file for
 * point 0 and M-1 sets of random data for points 1 to M-1, it will
 * create a Lagrange interpolating polynomial of degree M which is
 * random except that its value at 0 is given by secret.txt; its value
 * at any point other than 0 is random.  Given M such values, the
 * polynomial can be recovered, hence, in particular, its value at 0
 * (the secret). */

/* Concise mathematical details (you may skip this but read below):
 * We work in the Galois field F256 with 256 elements represented by
 * the integers from 0 to 255.  The two operations ("addition" and
 * "multiplication") of the field are the exclusive or and the Conway
 * multiplication.  Exclusive or can be defined (by induction) as
 *   a xor b = the smallest n not equal to a' xor b for a'<a
 *             nor to a xor b' for b'<b
 * Similarly, Conway multiplication can be defined as
 *   a conmul b = the smallest n not equal to
 *                (a' conmul b) xor (a' conmul b') xor (a conmul b')
 *                for some a'<a and b'<b
 * Note that 0 and 1 in the field are the true 0 and 1.
 * Note that the field has characteristic 2, so substraction is
 * precisely the same thing as addition (namely, exclusive or);
 * nevertheless I will write + and - as needed in what follows for
 * greater clarity.
 * Suppose zi are the output points and xj the input points (for
 * various values of i and j); suppose yj is the input data for input
 * point xj (i.e. one byte of the corresponding input file).  We wish
 * to compute the output data ti corresponding to zi.  The polynomial
 * (Conway) product of the (X-xk) for k not equal to j is equal to 0
 * at every xk except xj where it is not zero; we call in_cross[j] its
 * value at xj.  If we (Conway) divide the product of the (X-xk) by
 * in_cross[j] we get a polynomial which is 1 at xj and 0 at every
 * other xk: call it Pj.  The sum (i.e. XOR) of the yj Pj is the
 * Lagrange interpolating polynomial: it takes value yj at each xj.
 * So its value at zi is the sum of the yj Pj(zi).  Now Pj(zi) is the
 * product of the (zi-xk) for k not equal to j, divdided by
 * in_cross[j].  Call out_cross[i] the product of the (zi-xk) for
 * _every_ k.  Then Pj(zi) is out_cross[i] divided by the product of
 * (zi-xj) by in_cross[j].  This is expression is the horrible
 * conmul_tab[out_cross[i]][coninv_tab[conmul_tab[in_cross[j]]
 *     [out_points[i]^in_points[j]]]]
 * further down in this program (here out_points[i] is zi,
 * in_points[j] is xj and ^ is the XOR operation; and conmul_tab is
 * the table giving the Conway multiplication and coninv_tab is the
 * table giving the Conway inverse operation). */

/* Note: your secret sharing system will only be secure provided you
 * feed the program with _cryptographically secure random numbers_. */

/* [This Note is not valid in the below implementation.] */
/* Note: all input and output files are open simultaneously.  Your
 * system must have enough file descriptors. */

/* Speed estimation: circa 350kB/s on an Intel PIII-600 running Linux
 * with NM=30.  Speed decreases linearly in proportion with NM.  Thus
 * we have a theoretical speed of circa 10MB/s. */

/* Plea: although I put this file in the Public Domain, I would very
 * much appreciate getting credit if credit is due.  Thank you. */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "sss.h"

static void
error(
  const char *errmsg
){
  fprintf(stderr, "%s\n", errmsg);
  exit(EXIT_FAILURE);
}

int
main(
  int argc
 ,const char *argv[]
){
  const char **of;
  unsigned char *ip;
  unsigned char *op;
  unsigned char **iv;
  unsigned char **ov;
  unsigned int in;
  unsigned int on;
  unsigned int ln;
  unsigned int k;

  of = 0;
  ip = op = 0;
  iv = ov = 0;
  in = on = 0;
  ln = 0;
  /* Read command line arguments */
  for (k = 1; k < (unsigned int)argc; ++k) {
    void *v;
    unsigned int s;
    int l;
    int p;

    p = 0;
    for (l = 0; argv[k][l] >= '0' && argv[k][l] <= '9'; ++l) {
      p = p * 10 + (argv[k][l] - '0');
      if (p >= 256)
        error("Point value too large.");
    }
    if (argv[k][l] == '-') {
      unsigned int m;

      for (m = 0; m < in; ++m)
        if (*(ip + m) == p)
          error("Duplicate input point.");
      if (!(v = realloc(ip, (in + 1) * sizeof (*ip))))
        error("realloc.");
      ip = v;
      *(ip + in) = p;
      if (!(v = realloc(iv, (in + 1) * sizeof (*iv))))
        error("realloc.");
      iv = v;
      if ((p = open(argv[k] + l + 1, O_RDONLY)) < 0)
        error("Failed to open input file.");
      s = lseek(p, 0, SEEK_END);
      if (!ln)
        ln = s;
      else if (ln != s)
        error("not the same len.");
      if (!(*(iv + in) = malloc(ln)))
        error("malloc.");
      lseek(p, 0, SEEK_SET);
      if (read(p, *(iv + in), ln) != ln)
        error("read.");
      close(p);
      ++in;
    } else if (argv[k][l] == '+') {
      if (on >= 256)
        error("Too many output points.");
      if (!(v = realloc(op, (on + 1) * sizeof (*op))))
        error("realloc.");
      op = v;
      *(op + on) = p;
      if (!(v = realloc(ov, (on + 1) * sizeof (*ov))))
        error("realloc.");
      ov = v;
      if (!(*(ov + on) = malloc(ln)))
        error("malloc.");
      if (!(v = realloc(of, (on + 1) * sizeof (*of))))
        error("realloc.");
      of = v;
      *(of + on) = argv[k] + l + 1;
      ++on;
    } else
      error("Bad argument syntax.");
  }
  if (!in)
   error("No input files.");
  if (!on)
   error("No output files.");
  sss(ip, op, iv, ov, in, on, ln);
  for (k = 0; k < on; ++k) {
    int p;

    if ((p = open(*(of + k), O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0)
      error("Failed to open output file.");
    if (write(p, *(ov + k), ln) != ln)
      error("write.");
    close(p);
  }
  return (0);
}
