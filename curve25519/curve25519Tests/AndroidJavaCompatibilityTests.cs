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
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using org.whispersystems.curve25519;
using org.whispersystems.curve25519.csharp;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace curve25519Tests
{
    [TestClass]
    public class AndroidJavaCompatibilityTests
    {
        #region Test helper code
        private Curve25519 curve25519;
        private const int EXPECTED_LEN = 32;
        private static byte[] GetRandomBuffer(int expectedLen)
        {
            IBuffer randomIBuffer = CryptographicBuffer.GenerateRandom((uint)expectedLen);
            return WindowsRuntimeBufferExtensions.ToArray(randomIBuffer, 0, expectedLen);
        }
        #endregion

        [TestInitialize]
        public void Initialize()
        {
            //curve25519 = Curve25519.getInstance(Curve25519.BEST);
            curve25519 = Curve25519.getInstance(Curve25519.CSHARP);
        }

        [TestCleanup]
        public void Cleanup()
        {
            curve25519 = null;
        }

        [TestMethod]
        public void sha512_fast_test()
        {
            string sha512_input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
            byte[] sha512_correct_output = new byte[]
            {
                0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA,
                0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
                0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1,
                0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
                0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4,
                0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
                0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
                0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09
            };
            byte[] sha512_actual_output = new byte[64];

            BouncyCastleDotNETSha512Provider sha512provider = new BouncyCastleDotNETSha512Provider();
            sha512provider.calculateDigest(sha512_actual_output,
                Encoding.UTF8.GetBytes(sha512_input),
                sha512_input.Length);
            CollectionAssert.AreEqual(sha512_correct_output, sha512_actual_output, "SHA512 #1");

            var tmp = Encoding.UTF8.GetBytes(sha512_input);
            tmp[111] ^= 1;
            sha512_input = Encoding.UTF8.GetString(tmp);

            sha512provider.calculateDigest(sha512_actual_output,
                Encoding.UTF8.GetBytes(sha512_input),
                sha512_input.Length);
            CollectionAssert.AreNotEqual(sha512_correct_output, sha512_actual_output, "SHA512 #2");
        }

        [TestMethod]
        public void ge_is_small_order_test()
        {
            Ge_p3 o1 = new Ge_p3();
            Ge_p3 o2 = new Ge_p3();
            Ge_p3 o4a = new Ge_p3();
            Ge_p3 o4b = new Ge_p3();

            int[] zero = new int[10];
            int[] one = new int[10];
            int[] minusone = new int[10];

            Fe_0.fe_0(zero);
            Fe_1.fe_1(one);
            Fe_sub.fe_sub(minusone, zero, one);

            // o1 is the neutral point (order 1)
            Fe_copy.fe_copy(o1.X, zero);
            Fe_copy.fe_copy(o1.Y, one);
            Fe_copy.fe_copy(o1.Z, one);
            Fe_mul.fe_mul(o1.T, o1.X, o1.Y);

            // o2 is the order 2 point
            Fe_copy.fe_copy(o2.X, zero);
            Fe_copy.fe_copy(o2.Y, minusone);
            Fe_copy.fe_copy(o2.Z, one);
            Fe_mul.fe_mul(o2.T, o2.X, o2.Y);

            /* TODO check order 4 and 8 points */
            Assert.IsTrue(Ge_is_small_order.ge_is_small_order(o1) != 0 && Ge_is_small_order.ge_is_small_order(o2) != 0, "ge_is_small_order #1");

            Ge_p3 B0 = new Ge_p3();
            Ge_p3 B1 = new Ge_p3();
            Ge_p3 B2 = new Ge_p3();
            Ge_p3 B100 = new Ge_p3();
            byte[] scalar = new byte[32];

            Ge_scalarmult_base.ge_scalarmult_base(B0, scalar);
            scalar[0] = 1;
            Ge_scalarmult_base.ge_scalarmult_base(B1, scalar);
            scalar[0] = 2;
            Ge_scalarmult_base.ge_scalarmult_base(B2, scalar);
            scalar[0] = 100;
            Ge_scalarmult_base.ge_scalarmult_base(B100, scalar);

            int b0 = Ge_is_small_order.ge_is_small_order(B0);
            int b1 = Ge_is_small_order.ge_is_small_order(B1);
            int b2 = Ge_is_small_order.ge_is_small_order(B2);
            int b100 = Ge_is_small_order.ge_is_small_order(B100);

            Assert.IsTrue(Ge_is_small_order.ge_is_small_order(B0) != 0 &&
                Ge_is_small_order.ge_is_small_order(B1) == 0 &&
                Ge_is_small_order.ge_is_small_order(B2) == 0 &&
                Ge_is_small_order.ge_is_small_order(B100) == 0,
                "ge_is_small_order #2");

        }

        [TestMethod]
        public void elligator_fast_test()
        {
            byte[] elligator_correct_output = new byte[]
            {
                0x5f, 0x35, 0x20, 0x00, 0x1c, 0x6c, 0x99, 0x36,
                0xa3, 0x12, 0x06, 0xaf, 0xe7, 0xc7, 0xac, 0x22,
                0x4e, 0x88, 0x61, 0x61, 0x9b, 0xf9, 0x88, 0x72,
                0x44, 0x49, 0x15, 0x89, 0x9d, 0x95, 0xf4, 0x6e
            };

            byte[] hashtopoint_correct_output1 = new byte[]
            {
                0xce, 0x89, 0x9f, 0xb2, 0x8f, 0xf7, 0x20, 0x91,
                0x5e, 0x14, 0xf5, 0xb7, 0x99, 0x08, 0xab, 0x17,
                0xaa, 0x2e, 0xe2, 0x45, 0xb4, 0xfc, 0x2b, 0xf6,
                0x06, 0x36, 0x29, 0x40, 0xed, 0x7d, 0xe7, 0xed
            };

            byte[] hashtopoint_correct_output2 = new byte[]
            {
                0xa0, 0x35, 0xbb, 0xa9, 0x4d, 0x30, 0x55, 0x33,
                0x0d, 0xce, 0xc2, 0x7f, 0x83, 0xde, 0x79, 0xd0,
                0x89, 0x67, 0x72, 0x4c, 0x07, 0x8d, 0x68, 0x9d,
                0x61, 0x52, 0x1d, 0xf9, 0x2c, 0x5c, 0xba, 0x77
            };

            byte[] calculateu_correct_output = new byte[]
            {
                0xa8, 0x36, 0xb5, 0x30, 0xd3, 0xe7, 0x65, 0x54,
                0x3e, 0x72, 0xc8, 0x87, 0x7d, 0xa4, 0x12, 0x6d,
                0x77, 0xbf, 0x22, 0x0b, 0x72, 0xd5, 0xad, 0x6b,
                0xb6, 0xc2, 0x16, 0xb2, 0x92, 0x5f, 0x0f, 0x2a
            };

            int count;

            int[] iIn = new int[10];
            int[] iOut = new int[10];
            byte[] bytes = new byte[32];
            Fe_0.fe_0(iIn);
            Fe_0.fe_0(iOut);
            for (count = 0; count < 32; count++)
            {
                bytes[count] = (byte)count;
            }
            Fe_frombytes.fe_frombytes(iIn, bytes);
            Elligator.elligator(iOut, iIn);
            Fe_tobytes.fe_tobytes(bytes, iOut);
            CollectionAssert.AreEqual(elligator_correct_output, bytes, "Elligator vector");

            /* Elligator(0) == 0 test */
            Fe_0.fe_0(iIn);
            Elligator.elligator(iOut, iIn);
            CollectionAssert.AreEqual(iOut, iIn, "Elligator(0) == 0");

            /* ge_montx_to_p2(0) -> order2 point test */
            int[] one = new int[10];
            int[] negone = new int[10];
            int[] zero = new int[10];
            Fe_1.fe_1(one);
            Fe_0.fe_0(zero);
            Fe_sub.fe_sub(negone, zero, one);
            Ge_p2 p2 = new Ge_p2();
            Ge_montx_to_p2.ge_montx_to_p2(p2, zero, 0);
            Assert.IsTrue(Fe_isequal.fe_isequal(p2.X, zero) != 0 &&
                Fe_isequal.fe_isequal(p2.Y, negone) != 0 &&
                Fe_isequal.fe_isequal(p2.Z, one) != 0,
                "ge_montx_to_p2(0) == order 2 point");

            /* Hash to point vector test */
            Ge_p3 p3 = new Ge_p3();
            byte[] htp = new byte[32];

            for (count = 0; count < 32; count++)
            {
                htp[count] = (byte)count;
            }

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
            Elligator.hash_to_point(sha512provider, p3, htp, 32);
            Ge_p3_tobytes.ge_p3_tobytes(htp, p3);
            CollectionAssert.AreEqual(hashtopoint_correct_output1, htp, "hash_to_point #1");

            for (count = 0; count < 32; count++)
            {
                htp[count] = (byte)(count + 1);
            }

            Elligator.hash_to_point(sha512provider, p3, htp, 32);
            Ge_p3_tobytes.ge_p3_tobytes(htp, p3);
            CollectionAssert.AreEqual(hashtopoint_correct_output2, htp, "hash_to_point #2");

            /* calculate_U vector test */
            Ge_p3 Bu = new Ge_p3();
            byte[] U = new byte[32];
            byte[] Ubuf = new byte[200];
            byte[] a = new byte[32];
            byte[] Umsg = new byte[3];
            Umsg[0] = 0;
            Umsg[1] = 1;
            Umsg[2] = 2;
            for (count = 0; count < 32; count++)
            {
                a[count] = (byte)(8 + count);
            }
            Sc_clamp.sc_clamp(a);
            Elligator.calculate_Bu_and_U(sha512provider, Bu, U, Ubuf, a, Umsg, 3);

            CollectionAssert.AreEqual(calculateu_correct_output, U, "calculate_Bu_and_U vector");
        }

        [TestMethod]
        public void curvesigs_fast_test()
        {
            byte[] signature_correct = new byte[]
            {
                0xcf, 0x87, 0x3d, 0x03, 0x79, 0xac, 0x20, 0xe8,
                0x89, 0x3e, 0x55, 0x67, 0xee, 0x0f, 0x89, 0x51,
                0xf8, 0xdb, 0x84, 0x0d, 0x26, 0xb2, 0x43, 0xb4,
                0x63, 0x52, 0x66, 0x89, 0xd0, 0x1c, 0xa7, 0x18,
                0xac, 0x18, 0x9f, 0xb1, 0x67, 0x85, 0x74, 0xeb,
                0xdd, 0xe5, 0x69, 0x33, 0x06, 0x59, 0x44, 0x8b,
                0x0b, 0xd6, 0xc1, 0x97, 0x3f, 0x7d, 0x78, 0x0a,
                0xb3, 0x95, 0x18, 0x62, 0x68, 0x03, 0xd7, 0x82,
            };
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[64];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];

            privkey[8] = 189; /* just so there's some bits set */
            Sc_clamp.sc_clamp(privkey);

            /* Signature vector test */
            Keygen.curve25519_keygen(pubkey, privkey);

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
            Curve_sigs.curve25519_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

            CollectionAssert.AreEqual(signature_correct, signature, "Curvesig sign");

            Assert.AreEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "Curvesig verify #1");

            signature[0] ^= 1;

            Assert.AreNotEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "Curvesig verify #2");
        }

        [TestMethod]
        public void xdsa_fast_test()
        {
            byte[] signature_correct = new byte[]
            {
                0x11, 0xc7, 0xf3, 0xe6, 0xc4, 0xdf, 0x9e, 0x8a,
                0x51, 0x50, 0xe1, 0xdb, 0x3b, 0x30, 0xf9, 0x2d,
                0xe3, 0xa3, 0xb3, 0xaa, 0x43, 0x86, 0x56, 0x54,
                0x5f, 0xa7, 0x39, 0x0f, 0x4b, 0xcc, 0x7b, 0xb2,
                0x6c, 0x43, 0x1d, 0x9e, 0x90, 0x64, 0x3e, 0x4f,
                0x0e, 0xaa, 0x0e, 0x9c, 0x55, 0x77, 0x66, 0xfa,
                0x69, 0xad, 0xa5, 0x76, 0xd6, 0x3d, 0xca, 0xf2,
                0xac, 0x32, 0x6c, 0x11, 0xd0, 0xb9, 0x77, 0x02,
            };
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[64];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];

            privkey[8] = 189; /* just so there's some bits set */
            Sc_clamp.sc_clamp(privkey);

            /* Signature vector test */
            Keygen.curve25519_keygen(pubkey, privkey);

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();

            xdsa.xdsa_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

            CollectionAssert.AreEqual(signature_correct, signature, "XDSA sign");

            Assert.AreEqual(0, xdsa.xdsa_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "XDSA verify #1");

            signature[0] ^= 1;

            Assert.AreNotEqual(0, xdsa.xdsa_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "XDSA verify #2");
        }

        [TestMethod]
        public void uxdsa_fast_test()
        {
            byte[] signature_correct = new byte[]
            {
                0x66, 0x51, 0x0b, 0x68, 0x9e, 0xb7, 0xd8, 0x55,
                0x04, 0x62, 0xaf, 0x52, 0x0c, 0x89, 0x69, 0xe8,
                0xa9, 0xa5, 0x3d, 0xf3, 0x8e, 0xd6, 0xe6, 0x0f,
                0xe8, 0xfe, 0xd6, 0xa8, 0x95, 0x66, 0x9c, 0x19,
                0x66, 0x4a, 0x65, 0x25, 0xff, 0xb7, 0x47, 0x74,
                0x8e, 0x86, 0x40, 0x55, 0x0f, 0xb1, 0x4a, 0xd1,
                0x6d, 0xe0, 0x3d, 0x51, 0xa2, 0xd3, 0x4d, 0xee,
                0x64, 0x7e, 0x35, 0x98, 0x42, 0x25, 0x5a, 0x02,
                0xf8, 0x8c, 0x1e, 0x23, 0x5b, 0xd5, 0x7f, 0xb9,
                0x98, 0x60, 0x55, 0x63, 0xd6, 0xe0, 0x6d, 0xa1,
                0x29, 0xd9, 0xfc, 0xee, 0x1c, 0x08, 0x6d, 0x5a,
                0x28, 0xa1, 0x27, 0xf0, 0x06, 0xb9, 0x79, 0x03
            };
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[96];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];

            privkey[8] = 189; /* just so there's some bits set */
            Sc_clamp.sc_clamp(privkey);

            /* Signature vector test */
            Keygen.curve25519_keygen(pubkey, privkey);

            ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();

            uxdsa.uxdsa_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

            CollectionAssert.AreEqual(signature_correct, signature, "UXDSA sign");

            Assert.AreEqual(0, uxdsa.uxdsa_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "UXDSA verify #1");

            signature[0] ^= 1;

            Assert.AreNotEqual(0, uxdsa.uxdsa_verify(sha512provider, signature, pubkey, msg, MSG_LEN), "UXDSA verify #2");

            /* Test U */
            byte[] sigprev = new byte[96];
            Array.Copy(signature, 0, sigprev, 0, 96);
            sigprev[0] ^= 1; /* undo prev disturbance */

            random[0] ^= 1;
            uxdsa.uxdsa_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

            byte[] sig0 = new byte[32];
            Array.Copy(signature, 0, sig0, 0, 32);
            byte[] sigprev0 = new byte[32];
            Array.Copy(sigprev, 0, sigprev0, 0, 32);
            CollectionAssert.AreEqual(sigprev0, sig0, "UXDSA U value changed");

            byte[] sig32 = new byte[64];
            Array.Copy(signature, 32, sig32, 0, 64);
            byte[] sigprev32 = new byte[64];
            Array.Copy(sigprev, 32, sigprev32, 0, 64);
            CollectionAssert.AreNotEqual(sigprev32, sig32, "UXDSA (h, s) changed");
        }

        [TestMethod]
        public void curvesigs_slow_test()
        {
            int iterations = 10000;
            byte[] signature_10k_correct = new byte[]
            {
                0xfc, 0xba, 0x55, 0xc4, 0x85, 0x4a, 0x42, 0x25,
                0x19, 0xab, 0x08, 0x8d, 0xfe, 0xb5, 0x13, 0xb6,
                0x0d, 0x24, 0xbb, 0x16, 0x27, 0x55, 0x71, 0x48,
                0xdd, 0x20, 0xb1, 0xcd, 0x2a, 0xd6, 0x7e, 0x35,
                0xef, 0x33, 0x4c, 0x7b, 0x6d, 0x94, 0x6f, 0x52,
                0xec, 0x43, 0xd7, 0xe6, 0x35, 0x24, 0xcd, 0x5b,
                0x5d, 0xdc, 0xb2, 0x32, 0xc6, 0x22, 0x53, 0xf3,
                0x38, 0x02, 0xf8, 0x28, 0x28, 0xc5, 0x65, 0x05,
            };

            int count;
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[64];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];
            /* Signature random test */
            Debug.WriteLine("Pseudorandom curvesigs...");
            for (count = 1; count <= iterations; count++)
            {
                byte[] b = new byte[64];
                ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
                sha512provider.calculateDigest(b, signature, 64);
                Array.Copy(b, 0, privkey, 0, 32);
                sha512provider.calculateDigest(b, privkey, 32);
                Array.Copy(b, 0, random, 0, 64);

                Sc_clamp.sc_clamp(privkey);
                Keygen.curve25519_keygen(pubkey, privkey);

                Curve_sigs.curve25519_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

                Assert.AreEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"Curvesig verify failure #1 {count}");

                if ((b[63] & 1) != 0)
                {
                    signature[count % 64] ^= 1;
                }
                else
                {
                    msg[count % MSG_LEN] ^= 1;
                }
                Assert.AreNotEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"Curvesig verify failure #2 {count}");

                if (count == 10000)
                {
                    CollectionAssert.AreEqual(signature_10k_correct, signature, $"Curvesig signature 10K doesn't match {count}");
                }
            }
        }

        [TestMethod]
        public void xdsa_slow_test()
        {
            int iterations = 10000;
            byte[] signature_10k_correct = new byte[]
            {
                0x15, 0x29, 0x03, 0x38, 0x66, 0x16, 0xcd, 0x26,
                0xbb, 0x3e, 0xec, 0xe2, 0x9f, 0x72, 0xa2, 0x5c,
                0x7d, 0x05, 0xc9, 0xcb, 0x84, 0x3f, 0x92, 0x96,
                0xb3, 0xfb, 0xb9, 0xdd, 0xd6, 0xed, 0x99, 0x04,
                0xc1, 0xa8, 0x02, 0x16, 0xcf, 0x49, 0x3f, 0xf1,
                0xbe, 0x69, 0xf9, 0xf1, 0xcc, 0x16, 0xd7, 0xdc,
                0x6e, 0xd3, 0x78, 0xaa, 0x04, 0xeb, 0x71, 0x51,
                0x9d, 0xe8, 0x7a, 0x5b, 0xd8, 0x49, 0x7b, 0x05,
            };

            int count;
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[96];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];

            for (int i = 0; i < 64; i++)
            {
                signature[i] = 1;
            }

            /* Signature random test */
            Debug.WriteLine("Pseudorandom XDSA...");
            for (count = 1; count <= iterations; count++)
            {
                byte[] b = new byte[64];
                ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
                sha512provider.calculateDigest(b, signature, 64);
                Array.Copy(b, 0, privkey, 0, 32);
                sha512provider.calculateDigest(b, privkey, 32);
                Array.Copy(b, 0, random, 0, 64);

                Sc_clamp.sc_clamp(privkey);
                Keygen.curve25519_keygen(pubkey, privkey);

                xdsa.xdsa_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

                Assert.AreEqual(0, xdsa.xdsa_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"XDSA verify failure #1 {count}");

                if ((b[63] & 1) != 0)
                {
                    signature[count % 64] ^= 1;
                }
                else
                {
                    msg[count % MSG_LEN] ^= 1;
                }
                Assert.AreNotEqual(0, xdsa.xdsa_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"XDSA verify failure #2 {count}");

                if (count == 10000)
                {
                    byte[] sig0 = new byte[64];
                    Array.Copy(signature, 0, sig0, 0, 64);
                    CollectionAssert.AreEqual(signature_10k_correct, sig0, $"XDSA signature 10K doesn't match {count}");
                }
            }
        }

        [TestMethod]
        public void xdsa_to_curvesigs_slow_test()
        {
            int iterations = 10000;
            byte[] signature_10k_correct = new byte[]
            {
                0x33, 0x50, 0xa8, 0x68, 0xcd, 0x9e, 0x74, 0x99,
                0xa3, 0x5c, 0x33, 0x75, 0x2b, 0x22, 0x03, 0xf8,
                0xb5, 0x0f, 0xea, 0x8c, 0x33, 0x1c, 0x68, 0x8b,
                0xbb, 0xf3, 0x31, 0xcf, 0x7c, 0x42, 0x37, 0x35,
                0xa0, 0x0e, 0x15, 0xb8, 0x5d, 0x2b, 0xe1, 0xa2,
                0x03, 0x77, 0x94, 0x3d, 0x13, 0x5c, 0xd4, 0x9b,
                0x6a, 0x31, 0xf4, 0xdc, 0xfe, 0x24, 0xad, 0x54,
                0xeb, 0xd2, 0x98, 0x47, 0xf1, 0xcc, 0xbf, 0x0d
            };

            int count;
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[96];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];

            for (int i = 0; i < 64; i++)
            {
                signature[i] = 2;
            }

            /* Signature random test */
            Debug.WriteLine("Pseudorandom XDSA/Curvesigs...");
            for (count = 1; count <= iterations; count++)
            {
                byte[] b = new byte[64];
                ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
                sha512provider.calculateDigest(b, signature, 64);
                Array.Copy(b, 0, privkey, 0, 32);
                sha512provider.calculateDigest(b, privkey, 32);
                Array.Copy(b, 0, random, 0, 64);

                Sc_clamp.sc_clamp(privkey);
                Keygen.curve25519_keygen(pubkey, privkey);

                xdsa.xdsa_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

                Assert.AreEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"XDSA/Curvesigs verify failure #1 {count}");

                if ((b[63] & 1) != 0)
                {
                    signature[count % 64] ^= 1;
                }
                else
                {
                    msg[count % MSG_LEN] ^= 1;
                }
                Assert.AreNotEqual(0, Curve_sigs.curve25519_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"XDSA/Curvesigs verify failure #2 {count}");

                if (count == 10000)
                {
                    byte[] sig0 = new byte[64];
                    Array.Copy(signature, 0, sig0, 0, 64);
                    CollectionAssert.AreEqual(signature_10k_correct, sig0, $"XDSA/Curvesigs signature 10K doesn't match {count}");
                }
            }
        }

        [TestMethod]
        public void uxdsa_slow_test()
        {
            int iterations = 10000;
            byte[] signature_10k_correct = new byte[]
            {
                0x2d, 0x2a, 0x69, 0x20, 0x0a, 0xe7, 0x76, 0xeb,
                0x08, 0xc0, 0x3b, 0x4f, 0x26, 0x82, 0xd5, 0x3c,
                0x97, 0xc6, 0xb7, 0x9c, 0x6a, 0xf6, 0x24, 0x91,
                0xe1, 0xf9, 0x8f, 0x4f, 0x23, 0xc4, 0xba, 0x28,
                0x4b, 0x60, 0x87, 0x07, 0xe5, 0x94, 0xcb, 0xda,
                0x1b, 0x03, 0x5a, 0xd4, 0xd0, 0x6d, 0xd9, 0xa0,
                0x6a, 0x07, 0xee, 0x7b, 0x98, 0x7c, 0xe1, 0xc4,
                0x91, 0x52, 0x0d, 0x08, 0x32, 0xd7, 0x10, 0x03,
                0xbd, 0x96, 0x34, 0x11, 0x0c, 0x44, 0x56, 0x95,
                0x8b, 0x87, 0xdb, 0x12, 0x97, 0xa9, 0x5a, 0x62,
                0x2a, 0x34, 0xb1, 0xb1, 0xe2, 0xb4, 0xf5, 0x3c,
                0x34, 0xb6, 0x69, 0x0b, 0x77, 0x0e, 0x49, 0x07,
            };

            int count;
            const int MSG_LEN = 200;
            byte[] privkey = new byte[32];
            byte[] pubkey = new byte[32];
            byte[] signature = new byte[96];
            byte[] msg = new byte[MSG_LEN];
            byte[] random = new byte[64];

            for (int i = 0; i < 96; i++)
            {
                signature[i] = 3;
            }

            Debug.WriteLine("Pseudorandom UXDSA...");
            for (count = 1; count <= iterations; count++)
            {
                byte[] b = new byte[64];
                ISha512 sha512provider = new BouncyCastleDotNETSha512Provider();
                sha512provider.calculateDigest(b, signature, 96);
                Array.Copy(b, 0, privkey, 0, 32);
                sha512provider.calculateDigest(b, privkey, 32);
                Array.Copy(b, 0, random, 0, 64);

                Sc_clamp.sc_clamp(privkey);
                Keygen.curve25519_keygen(pubkey, privkey);

                uxdsa.uxdsa_sign(sha512provider, signature, privkey, msg, MSG_LEN, random);

                Assert.AreEqual(0, uxdsa.uxdsa_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"UXDSA verify failure #1 {count}");

                if ((b[63] & 1) != 0)
                {
                    signature[count % 96] ^= 1;
                }
                else
                {
                    msg[count % MSG_LEN] ^= 1;
                }
                Assert.AreNotEqual(0, uxdsa.uxdsa_verify(sha512provider, signature, pubkey, msg, MSG_LEN), $"UXDSA verify failure #2 {count}");

                if (count == 10000)
                {
                    CollectionAssert.AreEqual(signature_10k_correct, signature, $"UXDSA 10K doesn't match {count}");
                }
            }
        }
    }
}
