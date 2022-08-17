

// ReSharper disable InconsistentNaming

namespace bls.NativeImport
{
    public abstract partial class Native
    {
        public abstract int blsInit(int curveType, int compiledTimeVar);
        public abstract int blsGetFrByteSize();
        public abstract int blsGetG1ByteSize();

        public abstract void blsIdSetInt(ref Id id, int x);
        public abstract int blsIdSetDecStr(ref Id id, byte[] buf, ulong bufSize);
        public abstract int blsIdSetHexStr(ref Id id, byte[] buf, ulong bufSize);
        public abstract ulong blsIdGetDecStr(byte[] buf, ulong maxBufSize, ref Id id);
        public abstract ulong blsIdGetHexStr(byte[] buf, ulong maxBufSize, ref Id id);

        public abstract ulong blsIdSerialize(byte[] buf, ulong maxBufSize, ref Id id);
        public abstract ulong blsSecretKeySerialize(
            byte[] buf, ulong maxBufSize, ref SecretKey sec);
        public abstract ulong blsPublicKeySerialize(
            byte[] buf, ulong maxBufSize, ref PublicKey pub);
        public abstract ulong blsSignatureSerialize(
            byte[] buf, ulong maxBufSize, ref Signature sig);
        public abstract ulong blsIdDeserialize(ref Id id, byte[] buf, ulong bufSize);
        public abstract ulong blsSecretKeyDeserialize(ref SecretKey sec, byte[] buf, ulong bufSize);
        public abstract ulong blsPublicKeyDeserialize(ref PublicKey pub, byte[] buf, ulong bufSize);
        public abstract ulong blsSignatureDeserialize(ref Signature sig, byte[] buf, ulong bufSize);

        public abstract unsafe int blsIdIsEqual(Id* lhs, Id* rhs);
        public abstract unsafe int blsSecretKeyIsEqual(SecretKey* lhs, SecretKey* rhs);
        public abstract unsafe int blsPublicKeyIsEqual(PublicKey* lhs, PublicKey* rhs);
        public abstract unsafe int blsSignatureIsEqual(Signature* lhs, Signature* rhs);
        // add
        public abstract unsafe void blsSecretKeyAdd(ref SecretKey sec, SecretKey* rhs);
        public abstract unsafe void blsPublicKeyAdd(ref PublicKey pub, PublicKey* rhs);
        public abstract unsafe void blsSignatureAdd(ref Signature sig, Signature* rhs);
        // sub
        public abstract unsafe void blsSecretKeySub(ref SecretKey sec, SecretKey* rhs);
        public abstract unsafe void blsPublicKeySub(ref PublicKey pub, PublicKey* rhs);
        public abstract unsafe void blsSignatureSub(ref Signature sig, Signature* rhs);

        // neg
        public abstract void blsSecretKeyNeg(ref SecretKey x);
        public abstract void blsPublicKeyNeg(ref PublicKey x);
        public abstract void blsSignatureNeg(ref Signature x);
        // mul Fr
        public abstract unsafe void blsSecretKeyMul(ref SecretKey sec, SecretKey* rhs);
        public abstract unsafe void blsPublicKeyMul(ref PublicKey pub, SecretKey* rhs);
        public abstract unsafe void blsSignatureMul(ref Signature sig, SecretKey* rhs);

        // mulVec
        public abstract unsafe int blsPublicKeyMulVec(
            ref PublicKey pub, PublicKey* pubVec, SecretKey* idVec, ulong n);
        public abstract unsafe int blsSignatureMulVec(
            ref Signature sig, Signature* sigVec, SecretKey* idVec, ulong n);
        // zero
        public abstract unsafe int blsSecretKeyIsZero(SecretKey* x);
        public abstract unsafe int blsPublicKeyIsZero(PublicKey* x);
        public abstract unsafe int blsSignatureIsZero(Signature* x);
        // hash buf and set
        public abstract int blsHashToSecretKey(ref SecretKey sec, byte[] buf, ulong bufSize);
        /*
	    set secretKey if system has /dev/urandom or CryptGenRandom
	    return 0 if success else -1
	*/
        public abstract int blsSecretKeySetByCSPRNG(ref SecretKey sec);

        public abstract unsafe void blsGetPublicKey(ref PublicKey pub, SecretKey* sec);
        public abstract unsafe void blsGetPop(ref Signature sig, SecretKey* sec);

        // return 0 if success
        public abstract unsafe int blsSecretKeyShare(
            ref SecretKey sec, SecretKey* msk, ulong k, Id* id);
        public abstract unsafe int blsPublicKeyShare(
            ref PublicKey pub, PublicKey* mpk, ulong k, Id* id);


        public abstract unsafe int blsSecretKeyRecover(
            ref SecretKey sec, SecretKey* secVec, Id* idVec, ulong n);
        public abstract unsafe int blsPublicKeyRecover(
            ref PublicKey pub, PublicKey* pubVec, Id* idVec, ulong n);
        public abstract unsafe int blsSignatureRecover(
            ref Signature sig, Signature* sigVec, Id* idVec, ulong n);

        public abstract unsafe void blsSign(
            ref Signature sig, SecretKey* sec, byte[] buf, ulong size);

        // return 1 if valid
        public abstract unsafe int blsVerify(
            Signature* sig, PublicKey* pub, byte[] buf, ulong size);
        public abstract unsafe int blsVerifyPop(
            Signature* sig, PublicKey* pub);

        public abstract unsafe int blsFastAggregateVerify(
            Signature* sig, PublicKey* pubVec, ulong n, byte[] msg, ulong msgSize);
        public abstract unsafe int blsAggregateVerifyNoCheck(
            Signature* sig, PublicKey* pubVec, Msg* msgVec, ulong msgSize, ulong n);

        public abstract int blsMultiVerify(
            ref Signature sigVec, ref PublicKey pubVec, ref Msg msgVec,
            ulong msgSize, ref SecretKey randVec, ulong randSize, ulong n, int threadN);

        public abstract int blsSecretKeySetHexStr(
            ref SecretKey sec, byte[] buf, ulong bufSize);
        public abstract unsafe ulong blsSecretKeyGetHexStr(
            byte[] buf, ulong maxBufSize, SecretKey* sec);
        public abstract int blsPublicKeySetHexStr(
            ref PublicKey pub, byte[] buf, ulong bufSize);
        public abstract ulong blsPublicKeyGetHexStr(
            byte[] buf, ulong maxBufSize, ref PublicKey pub);
        public abstract int blsSignatureSetHexStr(
            ref Signature sig, byte[] buf, ulong bufSize);
        public abstract unsafe ulong blsSignatureGetHexStr(
            byte[] buf, ulong maxBufSize, Signature* sig);
    }
}
