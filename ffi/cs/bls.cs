/**
	@file
	@brief C# interface of BLS signature
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
    @note
    use bls384_256 built by `mklib dll eth` to use Ethereum mode
*/

using System;
using bls.NativeImport;

namespace bls
{
    public class BLS
    {
        public const int BN254 = 0;
        public const int BLS12_381 = 5;
        public const bool isETH = true;

        const int IoEcComp = 512; // fixed byte representation
        public const int FR_UNIT_SIZE = 4;
        public const int FP_UNIT_SIZE = 6;
        public const int BLS_COMPILER_TIME_VAR_ADJ = isETH ? 200 : 0;
        public const int COMPILED_TIME_VAR = FR_UNIT_SIZE * 10 + FP_UNIT_SIZE + BLS_COMPILER_TIME_VAR_ADJ;

        public const int ID_UNIT_SIZE = FR_UNIT_SIZE;
        public const int SECRETKEY_UNIT_SIZE = FR_UNIT_SIZE;
        public const int PUBLICKEY_UNIT_SIZE = FP_UNIT_SIZE * 3 * (isETH ? 1 : 2);
        public const int SIGNATURE_UNIT_SIZE = FP_UNIT_SIZE * 3 * (isETH ? 2 : 1);

        public const int ID_SERIALIZE_SIZE = ID_UNIT_SIZE * 8;
        public const int SECRETKEY_SERIALIZE_SIZE = 32;
        public const int PUBLICKEY_SERIALIZE_SIZE = 48;
        public const int SIGNATURE_SERIALIZE_SIZE = 96;
        public const int MSG_SIZE = 32;

        public static bool MultiVerify(in Signature[] sigVec, in PublicKey[] pubVec, in Msg[] msgVec)
        {
            if (pubVec.Length != msgVec.Length) {
                    throw new ArgumentException("different length of pubVec and msgVec");
            }
            if (pubVec.Length != sigVec.Length)
            {
                throw new ArgumentException("different length of pubVec and sigVec");
            }
            ulong n = (ulong)pubVec.Length;
            if (n == 0) {
                throw new ArgumentException("pubVec is empty");
            }

            SecretKey[] randVec = new SecretKey[pubVec.Length];
            foreach (var rand in randVec)
            {
                rand.SetByCSPRNG();
            }

            return Native.Instance.blsMultiVerify(
                ref sigVec[0],
                ref pubVec[0],
                ref msgVec[0],
                MSG_SIZE,
                ref randVec[0],
                n,
                n,
                4) == 1;
        }
    }
}
