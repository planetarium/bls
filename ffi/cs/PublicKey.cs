using System;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using Planetarium.Cryptography.bls.NativeImport;

namespace Planetarium.Cryptography.bls
{
    /// <summary>
    /// A public key struct of BLS signature.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct PublicKey
    {
        private fixed ulong v[BLS.PUBLICKEY_UNIT_SIZE];

        /// <summary>
        /// Serializes the public key to a <see cref="byte"/> array.
        /// </summary>
        /// <returns>Returns a <see cref="byte"/> array representation of this public key.</returns>
        /// <exception cref="ArithmeticException">Thrown if serialization is failed.</exception>
        public byte[] Serialize()
        {
            ulong bufSize = (ulong)Native.Instance.blsGetG1ByteSize() * (BLS.isETH ? 1 : 2);
            byte[] buf = new byte[bufSize];
            ulong n = Native.Instance.blsPublicKeySerialize(buf, bufSize, ref this);
            if (n != bufSize)
            {
                throw new ArithmeticException("blsPublicKeySerialize");
            }

            return buf;
        }

        /// <summary>
        /// Deserializes the public key from a <see cref="byte"/> array.
        /// </summary>
        /// <param name="buf">A <see cref="byte"/> array representation of an public key.</param>
        /// <exception cref="ArithmeticException">Thrown if deserialization is failed.</exception>
        public void Deserialize(byte[] buf)
        {
            if (buf.Length != BLS.PUBLICKEY_SERIALIZE_SIZE)
            {
                throw new ArgumentException(
                    "buf length is not public key size.", nameof(buf));
            }

            ulong bufSize = (ulong)buf.Length;
            ulong n = Native.Instance.blsPublicKeyDeserialize(ref this, buf, bufSize);
            if (n == 0 || n != bufSize)
            {
                throw new ArithmeticException("blsPublicKeyDeserialize");
            }
        }

        /// <summary>
        /// Checks if the public key is equal to another public key.
        /// </summary>
        /// <param name="rhs">an <see cref="PublicKey"/> to check.</param>
        /// <returns>Returns <see langword="true"/> if both are equal, otherwise returns
        /// <see langword="false"/>.
        /// </returns>
        public bool IsEqual(in PublicKey rhs)
        {
            fixed (PublicKey* l = &this)
            {
                fixed (PublicKey* r = &rhs)
                {
                    return Native.Instance.blsPublicKeyIsEqual(l, r) != 0;
                }
            }
        }

        /// <summary>
        /// Checks if the public key has zero value.
        /// </summary>
        /// <returns>Returns <see langword="true"/> if value is zero, otherwise returns
        /// <see langword="false"/>.
        /// </returns>
        public bool IsZero()
        {
            fixed (PublicKey* l = &this)
            {
                return Native.Instance.blsPublicKeyIsZero(l) != 0;
            }
        }

        /// <summary>
        /// Sets an public key with ethereum serialization format.
        /// </summary>
        /// <param name="s">a string contains hexadecimal value to set. </param>
        /// <exception cref="ArgumentException">Thrown if setting attempt is failed.</exception>
        public void SetStr(string s)
        {
            byte[] arr = Encoding.UTF8.GetBytes(s);

            if (Native.Instance.blsPublicKeySetHexStr(ref this, arr, (ulong)arr.Length) != 0)
            {
                throw new ArgumentException("blsPublicKeySetStr:" + s);
            }
        }

        /// <summary>
        /// Gets an public key with ethereum serialization format.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown if getting attempt is failed.</exception>
        public string GetHexStr()
        {
            byte[] arr = new byte[1024];

            ulong size = Native.Instance.blsPublicKeyGetHexStr(arr, (ulong)arr.Length, ref this);
            if (size == 0)
            {
                throw new ArgumentException("blsPublicKeyGetStr");
            }

            arr = arr.Take((int)size).ToArray();
            return Encoding.UTF8.GetString(arr);
        }

        /// <summary>
        /// Aggregates with given public key.
        /// </summary>
        /// <param name="rhs">A <see cref="PublicKey"/> to aggregate.</param>
        public void Add(in PublicKey rhs)
        {
            fixed (PublicKey* r = &rhs)
            {
                Native.Instance.blsPublicKeyAdd(ref this, r);
            }
        }

        /// <summary>
        /// Subtracts with given public key.
        /// </summary>
        /// <param name="rhs">A <see cref="PublicKey"/> to subtract.</param>
        public void Sub(in PublicKey rhs)
        {
            fixed (PublicKey* r = &rhs)
            {
                Native.Instance.blsPublicKeySub(ref this, r);
            }
        }

        /// <summary>
        /// Negates this public key.
        /// </summary>
        public void Neg()
        {
            Native.Instance.blsPublicKeyNeg(ref this);
        }

        /// <summary>
        /// Multiplies this public key with given public key.
        /// </summary>
        /// <param name="rhs">A public key </param>
        public void Mul(in SecretKey rhs)
        {
            fixed (SecretKey* r = &rhs)
            {
                Native.Instance.blsPublicKeyMul(ref this, r);
            }
        }

        /// <summary>
        /// Verifies if this public key has signed with given message.
        /// </summary>
        /// <param name="sig">A signature.</param>
        /// <param name="buf">A message used in signing.</param>
        /// <returns>Returns <see langword="true"/> if given <see cref="Signature"/> is signed with
        /// public key, otherwise returns <see langword="false"/>.</returns>
        public bool Verify(in Signature sig, in Msg buf)
        {
            fixed (PublicKey* l = &this)
            {
                fixed (Signature* s = &sig)
                {
                    fixed (Msg* m = &buf)
                    {
                        return Native.Instance.blsVerify(s, l, m, BLS.MSG_SIZE) == 1;
                    }
                }
            }
        }

        /// <summary>
        /// Verifies if given Proof of Possession (PoP) is valid with this public key.
        /// </summary>
        /// <param name="pop">A proof of possession signature to verify.</param>
        /// <returns></returns>
        public bool VerifyPop(in Signature pop)
        {
            fixed (PublicKey* l = &this)
            {
                fixed (Signature* s = &pop)
                {
                    return Native.Instance.blsVerifyPop(s, l) == 1;
                }
            }
        }

        // publicKey = sum_{i=0}^{mpk.Length - 1} mpk[i] * id^i
        public static PublicKey SharePublicKey(in PublicKey[] mpk, in Id id)
        {
            unsafe
            {
                fixed (PublicKey* p = &mpk[0])
                {
                    fixed (Id* i = &id)
                    {
                        PublicKey pub;
                        if (Native.Instance.blsPublicKeyShare(
                                ref pub, p, (ulong)mpk.Length, i) != 0)
                        {
                            throw new ArgumentException("GetPublicKeyForId:" + id);
                        }

                        return pub;
                    }
                }
            }
        }

        public static PublicKey RecoverPublicKey(in PublicKey[] pubVec, in Id[] idVec)
        {
            unsafe
            {
                fixed (PublicKey* p = &pubVec[0])
                {
                    fixed (Id* i = &idVec[0])
                    {
                        PublicKey pub;
                        if (Native.Instance.blsPublicKeyRecover(
                                ref pub, p, i, (ulong)pubVec.Length) != 0)
                        {
                            throw new ArgumentException("Recover");
                        }

                        return pub;
                    }
                }
            }
        }

        public static PublicKey MulVec(in PublicKey[] pubVec, in SecretKey[] secVec)
        {
            unsafe
            {
                if (pubVec.Length != secVec.Length) {
                    throw new ArithmeticException("PublicKey.MulVec");
                }

                fixed (PublicKey* p = &pubVec[0])
                {
                    fixed (SecretKey* s = &secVec[0])
                    {
                        PublicKey pub;
                        Native.Instance.blsPublicKeyMulVec(ref pub, p, s, (ulong)pubVec.Length);

                        return pub;
                    }
                }
            }
        }
    }
}
