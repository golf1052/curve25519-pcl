/** 
 * Copyright (C) 2016 golf1052
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;

namespace org.whispersystems.curve25519.csharp
{
    public class Elligator
    {
        public static int legendre_is_nonsquare(int[] iIn)
        {
            int[] temp = new int[10];
            Fe_pow22523.fe_pow22523(temp, iIn); /* temp = in^((q-5)/8) */
            Fe_sq.fe_sq(temp, temp);            /*        in^((q-5)/4) */
            Fe_sq.fe_sq(temp, temp);            /*        in^((q-5)/2) */
            Fe_mul.fe_mul(temp, temp, iIn);     /*        in^((q-3)/2) */
            Fe_mul.fe_mul(temp, temp, iIn);     /*        in^((q-1)/2) */


            /* temp is now the Legendre symbol:
             * 1 = square
             * 0 = input is zero
             * -1 = nonsquare
             */
            byte[] bytes = new byte[32];
            Fe_tobytes.fe_tobytes(bytes, temp);
            return 1 & bytes[31];
        }

        public static void elligator(int[] mont_x, int[] iIn)
        {
            /* r = in
             * v = -A/(1+2r^2)
             * e = (v^3 + Av^2 + v)^((q-1)/2) # legendre symbol
             * if e == 1 (square) or e == 0 (because v == 0 and 2r^2 + 1 == 0)
             *   out = v
             * if e == -1 (nonsquare)
             *   out = -v - A
             */

            int[] A = new int[10];
            int[] one = new int[10];
            int[] twor2 = new int[10];
            int[] twor2plus1 = new int[10];
            int[] twor2plus1inv = new int[10];
            int[] v = new int[10];
            int[] v2 = new int[10];
            int[] v3 = new int[10];
            int[] Av2 = new int[10];
            int[] e = new int[10];
            int[] u = new int[10];
            int[] Atemp = new int[10];
            int[] uneg = new int[10];
            int nonsquare;

            Fe_0.fe_0(one);
            one[0] = 1;                                         /* 1 */
            Fe_0.fe_0(A);
            A[0] = 486662;                                      /* A = 486662 */

            Fe_sq2.fe_sq2(twor2, iIn);                          /* 2r^2 */
            Fe_add.fe_add(twor2plus1, twor2, one);              /* 1+2r^2 */
            Fe_invert.fe_invert(twor2plus1inv, twor2plus1);     /* 1/(1+2r^2) */
            Fe_mul.fe_mul(v, twor2plus1inv, A);                 /* A/(1+2r^2) */
            Fe_neg.fe_neg(v, v);                                /* v = -A/(1+2r^2) */

            Fe_sq.fe_sq(v2, v);                                 /* v^2 */
            Fe_mul.fe_mul(v3, v2, v);                           /* v^3 */
            Fe_mul.fe_mul(Av2, v2, A);                          /* Av^2 */
            Fe_add.fe_add(e, v3, Av2);                          /* v^3 + Av^2 */
            Fe_add.fe_add(e, e, v);                             /* v^3 + Av^2 + v */
            nonsquare = legendre_is_nonsquare(e);

            Fe_0.fe_0(Atemp);
            Fe_cmov.fe_cmov(Atemp, A, nonsquare);               /* 0, or A if nonsquare */
            Fe_add.fe_add(u, v, Atemp);                         /* v, or v+A if nonsquare */
            Fe_neg.fe_neg(uneg, u);                             /* -v, or -v-A if nonsquare */
            Fe_cmov.fe_cmov(u, uneg, nonsquare);                /* v, or -v-A if nonsquare */
            Fe_copy.fe_copy(mont_x, u);
        }

        public static void hash_to_point(ISha512 sha512provider, Ge_p3 iOut, byte[] iIn, int in_len)
        {
            byte[] hash = new byte[64];
            int[] h = new int[10];
            int[] mont_x = new int[10];
            byte sign_bit;

            /* hash and elligator */
            sha512provider.calculateDigest(hash, iIn, in_len);

            sign_bit = (byte)(hash[31] & 0x80); /* take the high bit as Edwards sign bit */
            hash[31] &= 0x7F;
            Fe_frombytes.fe_frombytes(h, hash);

            elligator(mont_x, h);

            int[] ed_y = new int[10];
            byte[] ed_pubkey = new byte[32];

            Fe_montx_to_edy.fe_montx_to_edy(ed_y, mont_x);
            Fe_tobytes.fe_tobytes(ed_pubkey, ed_y);
            ed_pubkey[31] &= 0x7F; /* bit should be zero already, but just in case */
            ed_pubkey[31] |= sign_bit;

            /* decompress full point */
            /* WARNING - due to timing-variance, don't use with secret inputs! */
            Ge_frombytes.ge_frombytes_negate_vartime(iOut, ed_pubkey);

            /* undo the negation */
            Fe_neg.fe_neg(iOut.X, iOut.X);
            Fe_neg.fe_neg(iOut.T, iOut.T);

            /* multiply by 8 (cofactor) to map onto the main subgroup,
             * or map small-order points to the neutral element
             * (the latter prevents leaking r mod (2, 4, 8) via U) */
            Ge_p1p1 dbl_result = new Ge_p1p1();

            Ge_p3_dbl.ge_p3_dbl(dbl_result, iOut);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(iOut, dbl_result);

            Ge_p3_dbl.ge_p3_dbl(dbl_result, iOut);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(iOut, dbl_result);

            Ge_p3_dbl.ge_p3_dbl(dbl_result, iOut);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(iOut, dbl_result);
        }

        public static void calculate_Bu(ISha512 sha512provider, Ge_p3 Bu, byte[] buf, byte[] msg, int msg_len)
        {
            int count;

            /* Calculate SHA512(label(2) || msg) */
            buf[0] = 0xFD;
            for (count = 1; count < 32; count++)
            {
                buf[count] = 0xFF;
            }
            Array.Copy(msg, 0, buf, 32, msg_len);

            hash_to_point(sha512provider, Bu, buf, 32 + msg_len);
        }

        public static void calculate_Bu_and_U(ISha512 sha512provider, Ge_p3 Bu, byte[] U, byte[] buf, byte[] a, byte[] msg, int msg_len)
        {
            Ge_p3 p3 = new Ge_p3();

            calculate_Bu(sha512provider, Bu, buf, msg, msg_len);
            Ge_scalarmult.ge_scalarmult(p3, a, Bu);
            Ge_p3_tobytes.ge_p3_tobytes(U, p3);
        }
    }
}
