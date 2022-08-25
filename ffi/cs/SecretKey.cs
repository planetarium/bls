using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Planetarium.Cryptography.BLS12_381.NativeImport;

namespace Planetarium.Cryptography.BLS12_381
{
    /// <summary>
    /// A Secret key struct of BLS signature.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct SecretKey
    {
        private fixed ulong v[BLS.SECRETKEY_UNIT_SIZE];

        /// <summary>
        /// Serializes the SecretKey to a <see cref="byte"/> array.
        /// </summary>
        /// <returns>Returns a <see cref="byte"/> array representation of this SecretKey.</returns>
        /// <exception cref="ArithmeticException">Thrown if serialization is failed.</exception>
        public byte[] Serialize()
        {
            ulong bufSize = (ulong)Native.Instance.blsGetFrByteSize();
            byte[] buf = new byte[bufSize];
            ulong n = Native.Instance.blsSecretKeySerialize(buf, bufSize, ref this);
            if (n != bufSize)
            {
                throw new ArithmeticException("blsSecretKeySerialize");
            }

            return buf;
        }

        /// <summary>
        /// Deserializes the SecretKey from a <see cref="byte"/> array.
        /// </summary>
        /// <param name="buf">A <see cref="byte"/> array representation of an SecretKey.</param>
        /// <exception cref="ArithmeticException">Thrown if deserialization is failed.</exception>
        public void Deserialize(byte[] buf)
        {
            if (buf.Length != BLS.SECRETKEY_SERIALIZE_SIZE)
            {
                throw new ArgumentException("buf size is not secret key size.", nameof(buf));
            }

            ulong bufSize = (ulong)buf.Length;
            ulong n = Native.Instance.blsSecretKeyDeserialize(ref this, buf, bufSize);
            if (n == 0 || n != bufSize)
            {
                throw new ArithmeticException("blsSecretKeyDeserialize");
            }
        }

        /// <summary>
        /// Checks if the secret key is equal to another secret key.
        /// </summary>
        /// <param name="rhs">an <see cref="SecretKey"/> to check.</param>
        /// <returns>Returns <see langword="true"/> if both are equal, otherwise returns
        /// <see langword="false"/>.
        /// </returns>
        public bool IsEqual(in SecretKey rhs)
        {
            fixed (SecretKey* l = &this)
            {
                fixed (SecretKey* r = &rhs)
                {
                    return Native.Instance.blsSecretKeyIsEqual(l, r) != 0;
                }
            }
        }

        /// <summary>
        /// Checks if the private key has zero value.
        /// </summary>
        /// <returns>Returns <see langword="true"/> if value is zero, otherwise returns
        /// <see langword="false"/>.
        /// </returns>
        public bool IsZero()
        {
            fixed (SecretKey* l = &this)
            {
                return Native.Instance.blsSecretKeyIsZero(l) != 0;
            }
        }

        /// <summary>
        /// Sets a secret key with ethereum serialization format.
        /// </summary>
        /// <param name="s">a string contains hexadecimal value to set. </param>
        /// <exception cref="ArgumentException">Thrown if setting attempt is failed.</exception>
        public void SetHexStr(string s)
        {
            byte[] arr = Encoding.UTF8.GetBytes(s);

            if (Native.Instance.blsSecretKeySetHexStr(ref this, arr, (ulong)s.Length) != 0)
            {
                throw new ArgumentException("blsSecretKeySetHexStr:" + s);
            }
        }

        /// <summary>
        /// Gets a secret key with ethereum serialization format.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown if getting attempt is failed.</exception>
        public string GetHexStr()
        {
            fixed (SecretKey* s = &this)
            {
                byte[] arr = new byte[1024];

                ulong size = Native.Instance.blsSecretKeyGetHexStr(arr, (ulong)arr.Length, s);
                if (size == 0)
                {
                    throw new ArgumentException("blsSecretKeyGetHexStr");
                }

                arr = arr.Take((int)size).ToArray();
                return Encoding.UTF8.GetString(arr);
            }
        }

        /// <summary>
        /// Adds given secret key.
        /// </summary>
        /// <param name="rhs">A <see cref="SecretKey"/> to aggregate.</param>
        public void Add(in SecretKey rhs)
        {
            fixed (SecretKey* r = &rhs)
            {
                Native.Instance.blsSecretKeyAdd(ref this, r);
            }
        }

        /// <summary>
        /// Subtracts with given secret key.
        /// </summary>
        /// <param name="rhs">A <see cref="SecretKey"/> to subtract.</param>
        public void Sub(in SecretKey rhs)
        {
            fixed (SecretKey* r = &rhs)
            {
                Native.Instance.blsSecretKeySub(ref this, r);
            }
        }

        /// <summary>
        /// Negates this secret key.
        /// </summary>
        public void Neg()
        {
            Native.Instance.blsSecretKeyNeg(ref this);
        }

        /// <summary>
        /// Multiplies this secret key to a Fr.
        /// </summary>
        /// <param name="rhs">A Fr value.</param>
        public void Mul(in SecretKey rhs)
        {
            fixed (SecretKey* r = &rhs)
            {
                Native.Instance.blsSecretKeyMul(ref this, r);
            }
        }

        /// <summary>
        /// Sets a secret key by cryptographically secure pseudo random number generator.
        /// </summary>
        public void SetByCSPRNG()
        {
            Native.Instance.blsSecretKeySetByCSPRNG(ref this);
        }

        /// <summary>
        /// Sets a secret key by a hash of byte array buf.
        /// </summary>
        /// <param name="buf"></param>
        /// <exception cref="ArgumentException"></exception>
        public void SetHashOf(byte[] buf)
        {
            if (Native.Instance.blsHashToSecretKey(ref this, buf, (ulong)buf.Length) != 0)
            {
                throw new ArgumentException("blsHashToSecretKey");
            }
        }

        /// <summary>
        /// Sets a secret key by a hash of string s.
        /// </summary>
        /// <param name="s">A string.</param>
        public void SetHashOf(string s)
        {
            SetHashOf(Encoding.UTF8.GetBytes(s));
        }

        /// <summary>
        /// Gets the corresponding public key to a secret key
        /// </summary>
        /// <returns>Returns the corresponding public key.</returns>
        public PublicKey GetPublicKey()
        {
            fixed (SecretKey* sec = &this)
            {
                PublicKey pub;
                Native.Instance.blsGetPublicKey(ref pub, sec);
                return pub;
            }
        }

        /// <summary>
        /// Signs a message.
        /// </summary>
        /// <param name="buf">A message to sign.</param>
        /// <returns>Returns a signature of given message.</returns>
        public Signature Sign(in Msg buf)
        {
            fixed (SecretKey* sec = &this)
            {
                fixed (Msg* m = &buf)
                {
                    Signature sig;
                    Native.Instance.blsSign(ref sig, sec, m, BLS.MSG_SIZE);
                    return sig;
                }
            }
        }

        /// <summary>
        /// Gets a PoP (Proof Of Possession) for a secret key
        /// </summary>
        /// <returns>Returns a proof of possession of a secret key.</returns>
        public Signature GetPop()
        {
            fixed (SecretKey* l = &this)
            {
                Signature sig;
                Native.Instance.blsGetPop(ref sig, l);
                return sig;
            }
        }

        /// <summary>
        /// Generates the shared secret key from a sequence of master secret keys and identifier.
        /// </summary>
        /// <param name="msk">A array of master <see cref="SecretKey"/>s.</param>
        /// <param name="id">An identifier.</param>
        /// <returns>Returns a shared secret key.</returns>
        /// <exception cref="ArgumentException">Thrown if the generation has been failed.
        /// </exception>
        /// <remarks>secretKey = sum_{i=0}^{msk.Length - 1} msk[i] * id^i</remarks>
        public static SecretKey ShareSecretKey(in SecretKey[] msk, in Id id)
        {
            fixed (SecretKey* p = &msk[0])
            {
                fixed (Id* i = &id)
                {
                    SecretKey sec;
                    if (Native.Instance.blsSecretKeyShare(ref sec, p, (ulong)msk.Length, i) !=
                        0)
                    {
                        throw new ArgumentException("GetSecretKeyForId:" + id);
                    }

                    return sec;
                }
            }
        }

        /// <summary>
        /// Recovers the secret key from a sequence of secret keys secVec and idVec.
        /// </summary>
        /// <param name="secVec">The secret keys.</param>
        /// <param name="idVec">The identifiers.</param>
        /// <returns>Returns the recovered secret key.</returns>
        /// <exception cref="ArgumentException">Thrown if the recovering has been failed.
        /// </exception>
        public static SecretKey RecoverSecretKey(in SecretKey[] secVec, in Id[] idVec)
        {
            fixed (SecretKey* p = &secVec[0])
            {
                fixed (Id* i = &idVec[0])
                {
                    SecretKey sec;
                    if (Native.Instance.blsSecretKeyRecover(
                            ref sec, p, i, (ulong)secVec.Length) != 0)
                    {
                        throw new ArgumentException("blsSecretKeyRecover");
                    }

                    return sec;
                }
            }
        }
    }
}
