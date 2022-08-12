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
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using bls.NativeImport;

namespace mcl
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

        // ReSharper disable once InconsistentNaming
        public static int blsSecretKeySetByCSPRNG(ref BLS.SecretKey sec) =>
            Native.Instance.blsSecretKeySetByCSPRNG(ref sec);

        // don't call this if isETH = true, it calls in BLS()
        public static void Init(int curveType = BLS12_381) {
            if (isETH && isInit) return;
            if (isETH && curveType != BLS12_381) {
                throw new PlatformNotSupportedException("bad curveType");
            }
            if (!System.Environment.Is64BitProcess) {
                throw new PlatformNotSupportedException("not 64-bit system");
            }
            int err = Native.Instance.blsInit(curveType, COMPILED_TIME_VAR);
            if (err != 0) {
                throw new ArgumentException("blsInit");
            }
        }
        static readonly bool isInit;
        // call at once
        static BLS()
        {
            if (isETH) {
                Init(BLS12_381);
                isInit = true;
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct Id
        {
            private fixed ulong v[ID_UNIT_SIZE];
            public byte[] Serialize() {
                ulong bufSize = (ulong)Native.Instance.blsGetFrByteSize();
                byte[] buf = new byte[bufSize];
                ulong n = Native.Instance.blsIdSerialize(buf, bufSize, ref this);
                if (n != bufSize) {
                    throw new ArithmeticException("blsIdSerialize");
                }
                return buf;
            }
            public void Deserialize(byte[] buf) {
                ulong bufSize = (ulong)buf.Length;
                ulong n = Native.Instance.blsIdDeserialize(ref this, buf, bufSize);
                if (n == 0 || n != bufSize) {
                    throw new ArithmeticException("blsIdDeserialize");
                }
            }
            public bool IsEqual(in Id rhs)
            {
                fixed(Id *l = &this)
                {
                    fixed(Id *r = &rhs)
                    {
                        return Native.Instance.blsIdIsEqual(l, r) != 0;
                    }
                }

            }
            public void SetDecStr(string s)
            {
                char[] arr = s.ToCharArray();
                if (Native.Instance.blsIdSetDecStr(ref this, arr, (ulong)s.Length) != 0) {
                    throw new ArgumentException("blsIdSetDecStr:" + s);
                }
            }
            public void SetHexStr(string s) {
                char[] arr = s.ToCharArray();
                if (Native.Instance.blsIdSetHexStr(ref this, arr, (ulong)s.Length) != 0) {
                    throw new ArgumentException("blsIdSetDecStr:" + s);
                }
            }
            public void SetInt(int x) {
                Native.Instance.blsIdSetInt(ref this, x);
            }
            public string GetDecStr() {
                char[] arr = new char[1024];

                ulong size = Native.Instance.blsIdGetDecStr(ref arr, (ulong)arr.Length, ref this);
                if (size == 0)
                {
                    throw new ArgumentException("blsIdGetDecStr");
                }

                return new string(arr, 0, (int)size);
            }
            public string GetHexStr() {
                char[] arr = new char[1024];

                ulong size = Native.Instance.blsIdGetHexStr(ref arr, (ulong)arr.Length, ref this);
                if (size == 0)
                {
                    throw new ArgumentException("blsIdGetDecStr");
                }

                return new string(arr, 0, (int)size);
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct SecretKey
        {
            private fixed ulong v[SECRETKEY_UNIT_SIZE];
            public byte[] Serialize() {
                ulong bufSize = (ulong)Native.Instance.blsGetFrByteSize();
                byte[] buf = new byte[bufSize];
                ulong n = Native.Instance.blsSecretKeySerialize(buf, bufSize, ref this);
                if (n != bufSize) {
                    throw new ArithmeticException("blsSecretKeySerialize");
                }
                return buf;
            }
            public void Deserialize(byte[] buf) {
                ulong bufSize = (ulong)buf.Length;
                ulong n = Native.Instance.blsSecretKeyDeserialize(ref this, buf, bufSize);
                if (n == 0 || n != bufSize) {
                    throw new ArithmeticException("blsSecretKeyDeserialize");
                }
            }
            public bool IsEqual(in SecretKey rhs) {
                fixed (SecretKey* l = &this)
                {
                    fixed(SecretKey* r = &rhs)
                    {
                        return Native.Instance.blsSecretKeyIsEqual(l, r) != 0;
                    }
                }
            }
            public bool IsZero()
            {
                fixed(SecretKey* l = &this)
                {
                    return Native.Instance.blsSecretKeyIsZero(l) != 0;
                }
            }
            public void SetHexStr(string s) {
                char[] arr = s.ToCharArray();
                if (Native.Instance.blsSecretKeySetHexStr(ref this, arr, (ulong)s.Length) != 0) {
                    throw new ArgumentException("blsSecretKeySetHexStr:" + s);
                }
            }
            public string GetHexStr() {
                char[] arr = new char[1024];
                fixed (SecretKey* s = &this)
                {
                    ulong size = Native.Instance.blsSecretKeyGetHexStr(arr, (ulong)arr.Length, s);
                    if (size == 0) {
                        throw new ArgumentException("blsSecretKeyGetHexStr");
                    }

                    return new string(arr, 0, (int)size);
                }
            }
            public void Add(in SecretKey rhs) {
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
            public void SetByCSPRNG() {
                Native.Instance.blsSecretKeySetByCSPRNG(ref this);
            }
            public void SetHashOf(byte[] buf)
            {
                if (Native.Instance.blsHashToSecretKey(ref this, buf, (ulong)buf.Length) != 0) {
                    throw new ArgumentException("blsHashToSecretKey");
                }
            }
            public void SetHashOf(string s) {
                SetHashOf(Encoding.UTF8.GetBytes(s));
            }
            public PublicKey GetPublicKey() {
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
            public Signature GetPop() {
                fixed (SecretKey* l = &this)
                {
                    Signature sig;
                    Native.Instance.blsGetPop(ref sig, l);
                    return sig;
                }
            }
        }
        // secretKey = sum_{i=0}^{msk.Length - 1} msk[i] * id^i
        public static SecretKey ShareSecretKey(in SecretKey[] msk, in Id id) {
            unsafe
            {
                fixed (SecretKey* p = &msk[0])
                {
                    fixed (Id *i = &id)
                    {
                        SecretKey sec;
                        if (Native.Instance.blsSecretKeyShare(ref sec, p, (ulong)msk.Length, i) != 0) {
                            throw new ArgumentException("GetSecretKeyForId:" + id);
                        }
                        return sec;
                    }
                }
            }
        }
        public static SecretKey RecoverSecretKey(in SecretKey[] secVec, in Id[] idVec) {
            unsafe
            {
                fixed (SecretKey* p = &secVec[0])
                {
                    fixed (Id* i = &idVec[0])
                    {
                        SecretKey sec;
                        if (Native.Instance.blsSecretKeyRecover(ref sec, p, i, (ulong)secVec.Length) != 0) {
                            throw new ArgumentException("blsSecretKeyRecover");
                        }
                        return sec;
                    }
                }
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct PublicKey
        {
            private fixed ulong v[PUBLICKEY_UNIT_SIZE];
            public byte[] Serialize() {
                ulong bufSize = (ulong)Native.Instance.blsGetG1ByteSize() * (isETH ? 1 : 2);
                byte[] buf = new byte[bufSize];
                ulong n = Native.Instance.blsPublicKeySerialize(buf, bufSize, ref this);
                if (n != bufSize) {
                    throw new ArithmeticException("blsPublicKeySerialize");
                }
                return buf;
            }
            public void Deserialize(byte[] buf) {
                ulong bufSize = (ulong)buf.Length;
                ulong n = Native.Instance.blsPublicKeyDeserialize(ref this, buf, bufSize);
                if (n == 0 || n != bufSize) {
                    throw new ArithmeticException("blsPublicKeyDeserialize");
                }
            }
            public bool IsEqual(in PublicKey rhs) {
                fixed (PublicKey* l = &this)
                {
                    fixed(PublicKey* r = &rhs)
                    {
                        return Native.Instance.blsPublicKeyIsEqual(l, r) != 0;
                    }
                }
            }
            public bool IsZero()
            {
                fixed(PublicKey* l = &this)
                {
                    return Native.Instance.blsPublicKeyIsZero(l) != 0;
                }
            }
            public void SetStr(string s)
            {
                char[] arr = s.ToCharArray();
                if (Native.Instance.blsPublicKeySetHexStr(ref this, arr, (ulong)s.Length) != 0) {
                    throw new ArgumentException("blsPublicKeySetStr:" + s);
                }
            }
            public string GetHexStr() {
                char[] arr = new char[1024];
                fixed (PublicKey* p = &this)
                {
                    ulong size = Native.Instance.blsPublicKeyGetHexStr(arr, (ulong)arr.Length, p);
                    if (size == 0) {
                        throw new ArgumentException("blsPublicKeyGetStr");
                    }
                    return new string(arr, 0, (int)size);
                }
            }
            public void Add(in PublicKey rhs) {
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
            public bool Verify(in Signature sig, string s) {
                return Verify(sig, Encoding.UTF8.GetBytes(s));
            }
            public bool VerifyPop(in Signature pop) {
                fixed (PublicKey* l = &this)
                {
                    fixed(Signature* s = &pop)
                    {
                        return Native.Instance.blsVerifyPop(s, l) == 1;
                    }
                }
            }
        }
        // publicKey = sum_{i=0}^{mpk.Length - 1} mpk[i] * id^i
        public static PublicKey SharePublicKey(in PublicKey[] mpk, in Id id) {
            unsafe
            {
                fixed (PublicKey* p = &mpk[0])
                {
                    fixed (Id *i = &id)
                    {
                        PublicKey pub;
                        if (Native.Instance.blsPublicKeyShare(ref pub, p, (ulong)mpk.Length, i) != 0) {
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
                        if (Native.Instance.blsPublicKeyRecover(ref pub, p, i, (ulong)pubVec.Length) != 0) {
                            throw new ArgumentException("Recover");
                        }
                        return pub;
                    }
                }
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct Signature
        {
            private fixed ulong v[SIGNATURE_UNIT_SIZE];
            public byte[] Serialize() {
                ulong bufSize = (ulong)Native.Instance.blsGetG1ByteSize() * (isETH ? 2 : 1);
                byte[] buf = new byte[bufSize];
                ulong n = Native.Instance.blsSignatureSerialize(buf, bufSize, ref this);
                if (n != bufSize) {
                    throw new ArithmeticException("blsSignatureSerialize");
                }
                return buf;
            }
            public void Deserialize(byte[] buf) {
                ulong bufSize = (ulong)buf.Length;
                ulong n = Native.Instance.blsSignatureDeserialize(ref this, buf, bufSize);
                if (n == 0 || n != bufSize) {
                    throw new ArithmeticException("blsSignatureDeserialize");
                }
            }
            public bool IsEqual(in Signature rhs) {
                fixed (Signature* l = &this)
                {
                    fixed(Signature* r = &rhs)
                    {
                        return Native.Instance.blsSignatureIsEqual(l, r) != 0;
                    }
                }
            }
            public bool IsZero()
            {
                fixed(Signature* l = &this)
                {
                    return Native.Instance.blsSignatureIsZero(l) != 0;
                }
            }
            public void SetStr(string s)
            {
                char[] arr = s.ToCharArray();
                if (Native.Instance.blsSignatureSetHexStr(ref this, arr, (ulong)s.Length) != 0) {
                    throw new ArgumentException("blsSignatureSetStr:" + s);
                }
            }
            public string GetHexStr() {
                char[] arr = new char[1024];
                fixed (Signature* l = &this)
                {
                    ulong size = Native.Instance.blsSignatureGetHexStr(arr, (ulong)arr.Length, l);
                    if (size == 0) {
                        throw new ArgumentException("blsSignatureGetStr");
                    }
                    return new string(arr, 0, (int)size);
                }
            }
            public void Add(in Signature rhs) {
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
        }
        public static Signature RecoverSign(in Signature[] sigVec, in Id[] idVec)
        {
            unsafe
            {
                fixed (Signature* s = &sigVec[0])
                {
                    fixed (Id* i = &idVec[0])
                    {
                        Signature sig;
                        if (Native.Instance.blsSignatureRecover(ref sig, s, i, (ulong)sigVec.Length) != 0) {
                            throw new ArgumentException("Recover");
                        }
                        return sig;
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
        public static Signature MulVec(in Signature[] sigVec, in SecretKey[] secVec)
        {
            unsafe
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
        }
        public static bool FastAggregateVerify(in Signature sig, in PublicKey[] pubVec, byte[] msg)
        {
            unsafe
            {
                if (pubVec.Length == 0) {
                    throw new ArgumentException("pubVec is empty");
                }

                fixed(Signature* s = &sig)
                {
                    fixed(PublicKey* p = &pubVec[0])
                    {
                        return Native.Instance.blsFastAggregateVerify(s, p, (ulong)pubVec.Length, msg, (ulong)msg.Length) == 1;
                    }
                }
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct Msg
        {
            private fixed byte v[MSG_SIZE];
            public void Set(byte[] buf) {
                if (buf.Length != MSG_SIZE) {
                    throw new ArgumentException("bad buf size");
                }
                fixed (byte *p = v) {
                    for (int i = 0; i < MSG_SIZE; i++) {
                        p[i] = buf[i];
                    }
                }
            }
            public byte Get(int i)
            {
                fixed (byte *p = v) {
                    return p[i];
                }
            }
            public override int GetHashCode()
            {
                // FNV-1a 32-bit hash
                uint v = 2166136261;
                for (int i = 0; i < MSG_SIZE; i++) {
                    v ^= Get(i);
                    v *= 16777619;
                }
                return (int)v;
            }
            public override bool Equals(object obj)
            {
                if (!(obj is Msg)) return false;
                var rhs = (Msg)obj;
                for (int i = 0; i < MSG_SIZE; i++) {
                    if (Get(i) != rhs.Get(i)) return false;
                }
                return true;
            }
        }
        public static bool AreAllMsgDifferent(in Msg[] msgVec)
        {
            var set = new HashSet<Msg>();
            foreach (var msg in msgVec) {
                if (!set.Add(msg)) return false;
            }
            return true;
        }
        public static bool AggregateVerifyNoCheck(in Signature sig, in PublicKey[] pubVec, in Msg[] msgVec)
        {
            unsafe
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
                            return Native.Instance.blsAggregateVerifyNoCheck(s, p, m, MSG_SIZE, n) == 1;
                        }
                    }
                }
            }
        }
        public static bool AggregateVerify(in Signature sig, in PublicKey[] pubVec, in Msg[] msgVec)
        {
            if (!AreAllMsgDifferent(msgVec)) {
                return false;
            }
            return AggregateVerifyNoCheck(in sig, in pubVec, in msgVec);
        }

        public static bool MultiVerify(in Signature[] sigVec, in PublicKey[] pubVec, in Msg[] msgVec, in SecretKey[] randVec)
        {
            if (pubVec.Length != msgVec.Length) {
                    throw new ArgumentException("different length of pubVec and msgVec");
            }
            if (pubVec.Length != sigVec.Length)
            {
                throw new ArgumentException("different length of pubVec and sigVec");
            }
            if (pubVec.Length != randVec.Length)
            {
                throw new ArgumentException("different length of pubVec and randVec");
            }
            ulong n = (ulong)pubVec.Length;
            if (n == 0) {
                throw new ArgumentException("pubVec is empty");
            }

            return Native.Instance.blsMultiVerify(ref sigVec[0], ref pubVec[0], ref msgVec[0], MSG_SIZE, ref randVec[0], n, n, 4) == 1;
        }
    }
}
