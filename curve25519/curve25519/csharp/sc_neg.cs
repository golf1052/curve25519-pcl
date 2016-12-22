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

namespace org.whispersystems.curve25519.csharp
{
    public class Sc_neg
    {
        /* L = order of base point = 2^252 + 27742317777372353535851937790883648493 */

        /*
         * static unsigned char L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
         *                               0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
         *                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         *                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x10};
         */

        public static byte[] Lminus1 = new byte[32] {0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

        /* aneg = -a (mod L) */
        public static void sc_neg(byte[] aneg, byte[] a)
        {
            byte[] zero = new byte[32];
            //memset(zero, 0, 32);
            Sc_muladd.sc_muladd(aneg, Lminus1, a, zero); /* sneg = (-1)s + 0   (mod L) */
        }
    }
}
