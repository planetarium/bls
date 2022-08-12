using System;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using bls.NativeImport;

namespace bls
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct PublicKey
    {
        private fixed ulong v[BLS.PUBLICKEY_UNIT_SIZE];

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

        public void Deserialize(byte[] buf)
        {
            if (buf.Length != BLS.PUBLICKEY_SERIALIZE_SIZE)
            {
                throw new ArgumentException(
                    "buf length is not public key size.", nameof(buf));
            }
            if (buf.SequenceEqual(new byte[BLS.PUBLICKEY_SERIALIZE_SIZE]))
            {
                throw new ArgumentException("buf is zero", nameof(buf));
            }

            ulong bufSize = (ulong)buf.Length;
            ulong n = Native.Instance.blsPublicKeyDeserialize(ref this, buf, bufSize);
            if (n == 0 || n != bufSize)
            {
                throw new ArithmeticException("blsPublicKeyDeserialize");
            }
        }

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

        public bool IsZero()
        {
            fixed (PublicKey* l = &this)
            {
                return Native.Instance.blsPublicKeyIsZero(l) != 0;
            }
        }

        public void SetStr(string s)
        {
            byte[] arr = Encoding.UTF8.GetBytes(s);

            if (Native.Instance.blsPublicKeySetHexStr(ref this, arr, (ulong)arr.Length) != 0)
            {
                throw new ArgumentException("blsPublicKeySetStr:" + s);
            }
        }

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

        public void Add(in PublicKey rhs)
        {
            fixed (PublicKey* r = &rhs)
            {
                Native.Instance.blsPublicKeyAdd(ref this, r);
            }
        }

        public void Sub(in PublicKey rhs)
        {
            fixed (PublicKey* r = &rhs)
            {
                Native.Instance.blsPublicKeySub(ref this, r);
            }
        }

        public void Neg()
        {
            Native.Instance.blsPublicKeyNeg(ref this);
        }

        public void Mul(in SecretKey rhs)
        {
            fixed (SecretKey* r = &rhs)
            {
                Native.Instance.blsPublicKeyMul(ref this, r);
            }
        }

        public bool Verify(in Signature sig, byte[] buf)
        {
            fixed (PublicKey* l = &this)
            {
                fixed (Signature* s = &sig)
                {
                    return Native.Instance.blsVerify(s, l, buf, (ulong)buf.Length) == 1;
                }
            }
        }

        public bool Verify(in Signature sig, string s)
        {
            return Verify(sig, Encoding.UTF8.GetBytes(s));
        }

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
                        if (Native.Instance.blsPublicKeyShare(ref pub, p, (ulong)mpk.Length, i) !=
                            0)
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
