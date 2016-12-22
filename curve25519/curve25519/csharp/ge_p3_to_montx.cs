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
    public class Ge_p3_to_montx
    {
        public static void ge_p3_to_montx(int[] montx, Ge_p3 ed)
        {
            /*
             * mont_x = (ed_y + 1) / (1 - ed_y)
             * 
             * mont_x = (ed_y + ed_z) / (ed_z - ed_y)
             * 
             * NOTE: ed_y=1 is converted to mont_x=0 since fe_invert is mod-exp
             */

            int[] edy_plus_one = new int[10];
            int[] one_minus_edy = new int[10];
            int[] inv_one_minus_edy = new int[10];

            Fe_add.fe_add(edy_plus_one, ed.Y, ed.Z);
            Fe_sub.fe_sub(one_minus_edy, ed.Z, ed.Y);
            Fe_invert.fe_invert(inv_one_minus_edy, one_minus_edy);
            Fe_mul.fe_mul(montx, edy_plus_one, inv_one_minus_edy);
        }
    }
}
