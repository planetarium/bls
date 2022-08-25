using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Planetarium.Cryptography.bls.NativeImport;

namespace Planetarium.Cryptography.bls
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct Signature
    {
        private fixed ulong v[BLS.SIGNATURE_UNIT_SIZE];

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

        public bool IsZero()
        {
            fixed (Signature* l = &this)
            {
                return Native.Instance.blsSignatureIsZero(l) != 0;
            }
        }

        public void SetStr(string s)
        {
            byte[] arr = Encoding.UTF8.GetBytes(s);

            if (Native.Instance.blsSignatureSetHexStr(ref this, arr, (ulong)s.Length) != 0)
            {
                throw new ArgumentException("blsSignatureSetStr:" + s);
            }
        }

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

        public void Add(in Signature rhs)
        {
            fixed (Signature* r = &rhs)
            {
                Native.Instance.blsSignatureAdd(ref this, r);
            }
        }

        public void Sub(in Signature rhs)
        {
            fixed (Signature* r = &rhs)
            {
                Native.Instance.blsSignatureSub(ref this, r);
            }
        }

        public void Neg()
        {
            Native.Instance.blsSignatureNeg(ref this);
        }

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
