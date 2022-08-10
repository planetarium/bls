using mcl;

// ReSharper disable InconsistentNaming

namespace bls.NativeImport
{
    public abstract partial class Native
    {
        public abstract int blsInit(int curveType, int compiledTimeVar);
        public abstract int blsGetFrByteSize();
        public abstract int blsGetG1ByteSize();

        public abstract void blsIdSetInt(ref BLS.Id id, int x);
        public abstract int blsIdSetDecStr(ref BLS.Id id, char[] buf, ulong bufSize);
        public abstract int blsIdSetHexStr(ref BLS.Id id, char[] buf, ulong bufSize);
        public abstract ulong blsIdGetDecStr(ref char[] buf, ulong maxBufSize, ref BLS.Id id);
        public abstract ulong blsIdGetHexStr(ref char[] buf, ulong maxBufSize, ref BLS.Id id);

        public abstract ulong blsIdSerialize(byte[] buf, ulong maxBufSize, ref BLS.Id id);
        public abstract ulong blsSecretKeySerialize(byte[] buf, ulong maxBufSize, ref BLS.SecretKey sec);
        public abstract ulong blsPublicKeySerialize(byte[] buf, ulong maxBufSize, ref BLS.PublicKey pub);
        public abstract ulong blsSignatureSerialize(byte[] buf, ulong maxBufSize, ref BLS.Signature sig);
        public abstract ulong blsIdDeserialize(ref BLS.Id id, byte[] buf, ulong bufSize);
        public abstract ulong blsSecretKeyDeserialize(ref BLS.SecretKey sec, byte[] buf, ulong bufSize);
        public abstract ulong blsPublicKeyDeserialize(ref BLS.PublicKey pub, byte[] buf, ulong bufSize);
        public abstract ulong blsSignatureDeserialize(ref BLS.Signature sig, byte[] buf, ulong bufSize);

        public abstract unsafe int blsIdIsEqual(BLS.Id* lhs, BLS.Id* rhs);
        public abstract unsafe int blsSecretKeyIsEqual(BLS.SecretKey* lhs, BLS.SecretKey* rhs);
        public abstract unsafe int blsPublicKeyIsEqual(BLS.PublicKey* lhs, BLS.PublicKey* rhs);
        public abstract unsafe int blsSignatureIsEqual(BLS.Signature* lhs, BLS.Signature* rhs);
        // add
        public abstract unsafe void blsSecretKeyAdd(ref BLS.SecretKey sec, BLS.SecretKey* rhs);
        public abstract unsafe void blsPublicKeyAdd(ref BLS.PublicKey pub, BLS.PublicKey* rhs);
        public abstract unsafe void blsSignatureAdd(ref BLS.Signature sig, BLS.Signature* rhs);
        // sub
        public abstract unsafe void blsSecretKeySub(ref BLS.SecretKey sec, BLS.SecretKey* rhs);
        public abstract unsafe void blsPublicKeySub(ref BLS.PublicKey pub, BLS.PublicKey* rhs);
        public abstract unsafe void blsSignatureSub(ref BLS.Signature sig, BLS.Signature* rhs);

        // neg
        public abstract void blsSecretKeyNeg(ref BLS.SecretKey x);
        public abstract void blsPublicKeyNeg(ref BLS.PublicKey x);
        public abstract void blsSignatureNeg(ref BLS.Signature x);
        // mul Fr
        public abstract unsafe void blsSecretKeyMul(ref BLS.SecretKey sec, BLS.SecretKey* rhs);
        public abstract unsafe void blsPublicKeyMul(ref BLS.PublicKey pub, BLS.SecretKey* rhs);
        public abstract unsafe void blsSignatureMul(ref BLS.Signature sig, BLS.SecretKey* rhs);

        // mulVec
        public abstract unsafe int blsPublicKeyMulVec(ref BLS.PublicKey pub, BLS.PublicKey* pubVec, BLS.SecretKey* idVec, ulong n);
        public abstract unsafe int blsSignatureMulVec(ref BLS.Signature sig, BLS.Signature* sigVec, BLS.SecretKey* idVec, ulong n);
        // zero
        public abstract unsafe int blsSecretKeyIsZero(BLS.SecretKey* x);
        public abstract unsafe int blsPublicKeyIsZero(BLS.PublicKey* x);
        public abstract unsafe int blsSignatureIsZero(BLS.Signature* x);
        // hash buf and set
        public abstract int blsHashToSecretKey(ref BLS.SecretKey sec, byte[] buf, ulong bufSize);
        /*
	    set secretKey if system has /dev/urandom or CryptGenRandom
	    return 0 if success else -1
	*/
        public abstract int blsSecretKeySetByCSPRNG(ref BLS.SecretKey sec);

        public abstract unsafe void blsGetPublicKey(ref BLS.PublicKey pub, BLS.SecretKey* sec);
        public abstract unsafe void blsGetPop(ref BLS.Signature sig, BLS.SecretKey* sec);

        // return 0 if success
        public abstract unsafe int blsSecretKeyShare(ref BLS.SecretKey sec, BLS.SecretKey* msk, ulong k, BLS.Id* id);
        public abstract unsafe int blsPublicKeyShare(ref BLS.PublicKey pub, BLS.PublicKey* mpk, ulong k, BLS.Id* id);


        public abstract unsafe int blsSecretKeyRecover(ref BLS.SecretKey sec, BLS.SecretKey* secVec, BLS.Id* idVec, ulong n);
        public abstract unsafe int blsPublicKeyRecover(ref BLS.PublicKey pub, BLS.PublicKey* pubVec, BLS.Id* idVec, ulong n);
        public abstract unsafe int blsSignatureRecover(ref BLS.Signature sig, BLS.Signature* sigVec, BLS.Id* idVec, ulong n);

        public abstract unsafe void blsSign(ref BLS.Signature sig, BLS.SecretKey* sec, byte[] buf, ulong size);

        // return 1 if valid
        public abstract unsafe int blsVerify(BLS.Signature* sig, BLS.PublicKey* pub, byte[] buf, ulong size);
        public abstract unsafe int blsVerifyPop(BLS.Signature* sig, BLS.PublicKey* pub);

        public abstract unsafe int blsFastAggregateVerify(BLS.Signature* sig, BLS.PublicKey* pubVec, ulong n, byte[] msg, ulong msgSize);
        public abstract unsafe int blsAggregateVerifyNoCheck(BLS.Signature* sig, BLS.PublicKey* pubVec, BLS.Msg* msgVec, ulong msgSize, ulong n);

        public abstract int blsMultiVerify(ref BLS.Signature sigVec, ref BLS.PublicKey pubVec, ref BLS.Msg msgVec,
            ulong msgSize, ref BLS.SecretKey randVec, ulong randSize, ulong n, int threadN);

        public abstract int blsSecretKeySetHexStr(ref BLS.SecretKey sec, char[] buf, ulong bufSize);
        public abstract unsafe ulong blsSecretKeyGetHexStr(char[] buf, ulong maxBufSize, BLS.SecretKey* sec);
        public abstract int blsPublicKeySetHexStr(ref BLS.PublicKey pub, char[] buf, ulong bufSize);
        public abstract unsafe ulong blsPublicKeyGetHexStr(char[] buf, ulong maxBufSize, BLS.PublicKey* pub);
        public abstract int blsSignatureSetHexStr(ref BLS.Signature sig, char[] buf, ulong bufSize);
        public abstract unsafe ulong blsSignatureGetHexStr(char[] buf, ulong maxBufSize, BLS.Signature* sig);
    }
}
