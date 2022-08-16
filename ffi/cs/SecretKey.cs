using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using bls.NativeImport;

namespace bls
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct SecretKey
    {
        private fixed ulong v[BLS.SECRETKEY_UNIT_SIZE];

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

        public void Deserialize(byte[] buf)
        {
            if (buf.Length != BLS.SECRETKEY_SERIALIZE_SIZE)
            {
                throw new ArgumentException("buf size is not secret key size.", nameof(buf));
            }
            if (buf.SequenceEqual(new byte[BLS.SECRETKEY_SERIALIZE_SIZE]))
            {
                throw new ArgumentException("buf is zero", nameof(buf));
            }

            ulong bufSize = (ulong)buf.Length;
            ulong n = Native.Instance.blsSecretKeyDeserialize(ref this, buf, bufSize);
            if (n == 0 || n != bufSize)
            {
                throw new ArithmeticException("blsSecretKeyDeserialize");
            }
        }

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

        public bool IsZero()
        {
            fixed (SecretKey* l = &this)
            {
                return Native.Instance.blsSecretKeyIsZero(l) != 0;
            }
        }

        public void SetHexStr(string s)
        {
            byte[] arr = Encoding.UTF8.GetBytes(s);

            if (Native.Instance.blsSecretKeySetHexStr(ref this, arr, (ulong)s.Length) != 0)
            {
                throw new ArgumentException("blsSecretKeySetHexStr:" + s);
            }
        }

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

        public void Add(in SecretKey rhs)
        {
            fixed (SecretKey* r = &rhs)
            {
                Native.Instance.blsSecretKeyAdd(ref this, r);
            }
        }

        public void Sub(in SecretKey rhs)
        {
            fixed (SecretKey* r = &rhs)
            {
                Native.Instance.blsSecretKeySub(ref this, r);
            }
        }

        public void Neg()
        {
            Native.Instance.blsSecretKeyNeg(ref this);
        }

        public void Mul(in SecretKey rhs)
        {
            fixed (SecretKey* r = &rhs)
            {
                Native.Instance.blsSecretKeyMul(ref this, r);
            }
        }

        public void SetByCSPRNG()
        {
            Native.Instance.blsSecretKeySetByCSPRNG(ref this);
        }

        public void SetHashOf(byte[] buf)
        {
            if (Native.Instance.blsHashToSecretKey(ref this, buf, (ulong)buf.Length) != 0)
            {
                throw new ArgumentException("blsHashToSecretKey");
            }
        }

        public void SetHashOf(string s)
        {
            SetHashOf(Encoding.UTF8.GetBytes(s));
        }

        public PublicKey GetPublicKey()
        {
            fixed (SecretKey* sec = &this)
            {
                PublicKey pub;
                Native.Instance.blsGetPublicKey(ref pub, sec);
                return pub;
            }
        }

        public Signature Sign(byte[] buf)
        {
            fixed (SecretKey* sec = &this)
            {
                Signature sig;
                Native.Instance.blsSign(ref sig, sec, buf, (ulong)buf.Length);
                return sig;
            }
        }

        public Signature Sign(string s)
        {
            return Sign(Encoding.UTF8.GetBytes(s));
        }

        public Signature GetPop()
        {
            fixed (SecretKey* l = &this)
            {
                Signature sig;
                Native.Instance.blsGetPop(ref sig, l);
                return sig;
            }
        }

        // secretKey = sum_{i=0}^{msk.Length - 1} msk[i] * id^i
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
