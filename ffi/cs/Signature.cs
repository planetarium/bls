using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Planetarium.Cryptography.BLS12_381.NativeImport;

namespace Planetarium.Cryptography.BLS12_381
{
    /// <summary>
    /// A Signature struct of BLS signature.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct Signature
    {
        private fixed ulong v[BLS.SIGNATURE_UNIT_SIZE];

        /// <summary>
        /// Serializes the Signature to a <see cref="byte"/> array.
        /// </summary>
        /// <returns>Returns a <see cref="byte"/> array representation of this Signature.</returns>
        /// <exception cref="ArithmeticException">Thrown if serialization is failed.</exception>
        public byte[] Serialize()
        {
            ulong bufSize = (ulong)Native.Instance.blsGetG1ByteSize() * (BLS.isETH ? 2 : 1);
            byte[] buf = new byte[bufSize];
            ulong n = Native.Instance.blsSignatureSerialize(buf, bufSize, ref this);
            if (n != bufSize)
            {
                throw new ArithmeticException("blsSignatureSerialize");
            }

            return buf;
        }

        /// <summary>
        /// Deserializes the Signature from a <see cref="byte"/> array.
        /// </summary>
        /// <param name="buf">A <see cref="byte"/> array representation of an Signature.</param>
        /// <exception cref="ArithmeticException">Thrown if deserialization is failed.</exception>
        public void Deserialize(byte[] buf)
        {

            if (buf.Length != BLS.SIGNATURE_SERIALIZE_SIZE)
            {
                throw new ArgumentException(
                    "buf length is not signature size.", nameof(buf));
            }

            ulong bufSize = (ulong)buf.Length;
            ulong n = Native.Instance.blsSignatureDeserialize(ref this, buf, bufSize);
            if (n == 0 || n != bufSize)
            {
                throw new ArithmeticException("blsSignatureDeserialize");
            }
        }

        /// <summary>
        /// Checks if the public key is equal to another signature.
        /// </summary>
        /// <param name="rhs">an <see cref="Signature"/> to check.</param>
        /// <returns>Returns <see langword="true"/> if both are equal, otherwise returns
        /// <see langword="false"/>.
        /// </returns>
        public bool IsEqual(in Signature rhs)
        {
            fixed (Signature* l = &this)
            {
                fixed (Signature* r = &rhs)
                {
                    return Native.Instance.blsSignatureIsEqual(l, r) != 0;
                }
            }
        }

        /// <summary>
        /// Checks if the signature has zero value.
        /// </summary>
        /// <returns>Returns <see langword="true"/> if value is zero, otherwise returns
        /// <see langword="false"/>.
        /// </returns>
        public bool IsZero()
        {
            fixed (Signature* l = &this)
            {
                return Native.Instance.blsSignatureIsZero(l) != 0;
            }
        }

        /// <summary>
        /// Sets a signature with ethereum serialization format.
        /// </summary>
        /// <param name="s">a string contains hexadecimal value to set. </param>
        /// <exception cref="ArgumentException">Thrown if setting attempt is failed.</exception>
        public void SetStr(string s)
        {
            byte[] arr = Encoding.UTF8.GetBytes(s);

            if (Native.Instance.blsSignatureSetHexStr(ref this, arr, (ulong)s.Length) != 0)
            {
                throw new ArgumentException("blsSignatureSetStr:" + s);
            }
        }

        /// <summary>
        /// Gets a signature with ethereum serialization format.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown if getting attempt is failed.</exception>
        public string GetHexStr()
        {
            byte[] arr = new byte[1024];
            fixed (Signature* l = &this)
            {
                ulong size = Native.Instance.blsSignatureGetHexStr(arr, (ulong)arr.Length, l);
                if (size == 0)
                {
                    throw new ArgumentException("blsSignatureGetStr");
                }

                arr = arr.Take((int)size).ToArray();
                return Encoding.UTF8.GetString(arr);
            }
        }

        /// <summary>
        /// Adds given signature.
        /// </summary>
        /// <param name="rhs">A <see cref="Signature"/> to aggregate.</param>
        public void Add(in Signature rhs)
        {
            fixed (Signature* r = &rhs)
            {
                Native.Instance.blsSignatureAdd(ref this, r);
            }
        }

        /// <summary>
        /// Subtracts with given signature.
        /// </summary>
        /// <param name="rhs">A <see cref="Signature"/> to subtract.</param>
        public void Sub(in Signature rhs)
        {
            fixed (Signature* r = &rhs)
            {
                Native.Instance.blsSignatureSub(ref this, r);
            }
        }

        /// <summary>
        /// Negates this signature.
        /// </summary>
        public void Neg()
        {
            Native.Instance.blsSignatureNeg(ref this);
        }

        /// <summary>
        /// Multiplies this signature to a Fr.
        /// </summary>
        /// <param name="rhs">A Fr value.</param>
        public void Mul(in SecretKey rhs)
        {
            fixed (SecretKey* r = &rhs)
            {
                Native.Instance.blsSignatureMul(ref this, r);
            }
        }

        public static Signature RecoverSign(in Signature[] sigVec, in Id[] idVec)
        {
            fixed (Signature* s = &sigVec[0])
            {
                fixed (Id* i = &idVec[0])
                {
                    Signature sig;
                    if (Native.Instance.blsSignatureRecover(
                            ref sig, s, i, (ulong)sigVec.Length) != 0)
                    {
                        throw new ArgumentException("Recover");
                    }

                    return sig;
                }
            }
        }

        /// <summary>
        /// Multiplies the signatures to Frs.
        /// </summary>
        /// <param name="sigVec">A signatures.</param>
        /// <param name="secVec">A Fr values.</param>
        public static Signature MulVec(in Signature[] sigVec, in SecretKey[] secVec)
        {
            if (sigVec.Length != secVec.Length) {
                throw new ArithmeticException("Signature.MulVec");
            }
            fixed(Signature* s = &sigVec[0])
            {
                fixed(SecretKey* k = &secVec[0])
                {
                    Signature sig;
                    Native.Instance.blsSignatureMulVec(ref sig, s, k, (ulong)sigVec.Length);
                    return sig;
                }
            }
        }

        public bool FastAggregateVerify(in PublicKey[] pubVec, in Msg msg)
        {
            if (pubVec.Length == 0) {
                throw new ArgumentException("pubVec is empty");
            }

            fixed (Signature* s = &this)
            {
                fixed (PublicKey* p = &pubVec[0])
                {
                    fixed (Msg* m = &msg)
                    {
                        return Native.Instance.blsFastAggregateVerify(
                            s, p, (ulong)pubVec.Length, m, BLS.MSG_SIZE) == 1;
                    }
                }
            }
        }

        private static bool AggregateVerifyNoCheck(in Signature sig, in PublicKey[] pubVec, in Msg[] msgVec)
        {
            if (pubVec.Length != msgVec.Length) {
                throw new ArgumentException("different length of pubVec and msgVec");
            }
            ulong n = (ulong)pubVec.Length;
            if (n == 0) {
                throw new ArgumentException("pubVec is empty");
            }
            fixed (Signature* s = &sig)
            {
                fixed (PublicKey* p = &pubVec[0])
                {
                    fixed (Msg* m = &msgVec[0])
                    {
                        return Native.Instance.blsAggregateVerifyNoCheck(
                            s, p, m, BLS.MSG_SIZE, n) == 1;
                    }
                }
            }
        }

        public bool AggregateVerify(in PublicKey[] pubVec, in Msg[] msgVec) =>
            Msg.AreAllMsgDifferent(msgVec) &&
            AggregateVerifyNoCheck(in this, in pubVec, in msgVec);
    }
}
