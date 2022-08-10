#nullable enable
using System;
using System.Linq;
using System.Numerics;
using mcl;

namespace BLSWrapper
{
    /// <summary>
    /// A class for interfacing BLS digital signature library.
    /// </summary>
    public class BLSWrapper
    {
        // BLS library does have constant values for serialization, however, this has to be defined
        // again due to constant value is not same as actual byte length.

        /// <summary>
        /// The byte length of private key.
        /// </summary>
        internal const int PrivateKeySize = 32;

        /// <summary>
        /// The byte length of public key.
        /// </summary>
        internal const int PublicKeySize = 48;

        /// <summary>
        /// The byte length of signature.
        /// </summary>
        internal const int SignatureSize = 96;

        /// <summary>
        /// The byte length of message.
        /// </summary>
        internal const int MessageSize = BLS.MSG_SIZE;

        /// <summary>
        /// Generates a new private key with CSPRNG.
        /// </summary>
        /// <returns>Returns a new private key in <see langword="byte"/> array.</returns>
        public static byte[] GeneratePrivateKey()
        {
            BLS.SecretKey secretKey;
            _ = BLS.blsSecretKeySetByCSPRNG(ref secretKey);
            return secretKey.Serialize();
        }

        /// <summary>
        /// Get a public key from private key.
        /// </summary>
        /// <param name="privateKey">A private key for get a public key.</param>
        /// <returns>Returns <see langword="byte"/> array public key of given private key.</returns>
        /// <exception cref="BLSInvalidPrivateKeyException">Thrown if given length of private key is
        /// not <see cref="PrivateKeySize"/> or invalid.
        /// </exception>
        public static byte[] GetPublicKey(byte[] privateKey)
        {
            BLS.SecretKey secretKey;
            try
            {
                secretKey.Deserialize(privateKey);
                return secretKey.GetPublicKey().Serialize();
            }
            catch (ArithmeticException)
            {
                throw new BLSInvalidPrivateKeyException("Private key is invalid.");
            }
        }

        /// <summary>
        /// Verifies a signature with given public key and message.
        /// </summary>
        /// <param name="publicKey">A public key of given signature.</param>
        /// <param name="signature">A signature of given message.</param>
        /// <param name="message">A message created by signature.</param>
        /// <exception cref="ArgumentException">Thrown if given message length is not
        /// <see cref="MessageSize"/>.
        /// </exception>
        /// <exception cref="BLSInvalidPublicKeyException">Thrown if length of public key is not
        /// <see cref="PublicKeySize"/> or invalid.
        /// </exception>
        /// <exception cref="BLSInvalidSignatureException">Thrown if length of signature is not
        /// <see cref="SignatureSize"/> or invalid.
        /// </exception>
        /// <returns>Returns <see langword="true"/> if signature is valid with given public key and
        /// signature, otherwise returns <see langword="false"/>.
        /// </returns>
        public static bool Verify(byte[] publicKey, byte[] signature, byte[] message)
        {
            ValidatePublicKeyInput(publicKey);
            ValidateSignatureInput(signature);

            BLS.Signature sig;
            BLS.PublicKey pk;
            try
            {
                try
                {
                    pk.Deserialize(publicKey);
                }
                catch (ArithmeticException)
                {
                    throw new BLSInvalidPublicKeyException(
                        $"Public key is invalid. " +
                        $"(key: {pk.GetHexStr()})");
                }

                try
                {
                    sig.Deserialize(signature);
                }
                catch (ArithmeticException)
                {
                    throw new BLSInvalidSignatureException(
                        $"Signature is invalid. " +
                        $"(key: {sig.GetHexStr()})");
                }

                return pk.Verify(sig, message);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Signs a message with private key in this <see cref="BLSWrapper"/>.
        /// </summary>
        /// <param name="privateKey">A private key used to sign.</param>
        /// <param name="message">A message to sign.</param>
        /// <exception cref="ArgumentException">Thrown if given message length is not
        /// <see cref="MessageSize"/>.
        /// </exception>
        /// <exception cref="BLSInvalidPrivateKeyException">Thrown if given length of private key is
        /// not <see cref="PrivateKeySize"/> or invalid.
        /// </exception>
        /// <returns>Returns serialized signature in byte array.</returns>
        public static byte[] Sign(byte[] privateKey, byte[] message)
        {
            ValidateMessageInput(message);
            ValidatePrivateKeyInput(privateKey);

            BLS.SecretKey secretKey;
            try
            {
                secretKey.Deserialize(privateKey);
            }
            catch (ArithmeticException)
            {
                throw new BLSInvalidPrivateKeyException("Private key is invalid.");
            }

            BLS.Signature sig = secretKey.Sign(message);
            return sig.Serialize();
        }

        /// <summary>
        /// Verifies a message with given aggregated signature and used public keys.
        /// </summary>
        /// <param name="signature">A aggregated signature.</param>
        /// <param name="publicKeys">The public keys used to sign.</param>
        /// <param name="message">A message to verify.</param>
        /// <exception cref="ArgumentException">Thrown if no public key is given.</exception>
        /// <exception cref="BLSInvalidSignatureException">Thrown if length of signature is not
        /// <see cref="SignatureSize"/> or invalid.
        /// </exception>
        /// <exception cref="BLSInvalidPublicKeyException">Thrown if length of public key is not
        /// <see cref="PublicKeySize"/> or invalid.
        /// </exception>
        /// <returns>Returns <see langword="true"/> if inputs are valid, otherwise returns
        /// <see langword="false"/>.
        /// </returns>
        public static bool FastAggregateVerify(
            byte[] signature, byte[][] publicKeys, byte[] message)
        {
            if (publicKeys.Length == 0)
            {
                throw new ArgumentException(
                    "Public key cannot be empty.", nameof(publicKeys));
            }

            if (publicKeys.Length == 1)
            {
                return Verify(publicKeys[0], signature, message);
            }

            var sig = new BLS.Signature();
            ValidateSignatureInput(signature);
            try
            {
                sig.Deserialize(signature);
            }
            catch (ArithmeticException)
            {
                throw new BLSInvalidSignatureException("Signature is invalid.");
            }

            var pks = new BLS.PublicKey[publicKeys.Length];
            for (var i = 0; i < publicKeys.Length; i++)
            {
                ValidatePublicKeyInput(publicKeys[i]);
                try
                {
                    pks[i].Deserialize(publicKeys[i]);
                }
                catch (ArithmeticException)
                {
                    throw new BLSInvalidPublicKeyException(
                        $"Invalid public key contains in publicKeys." +
                        $" (key: {pks[i].GetHexStr()})");
                }
            }

            return BLS.FastAggregateVerify(sig, pks, message);
        }

        /// <summary>
        /// Verifies a message with given aggregated signature and used public keys.
        /// </summary>
        /// <param name="signature">A aggregated signature.</param>
        /// <param name="publicKeys">The public keys used to sign.</param>
        /// <param name="messages">A 32-bytes long messages.</param>
        /// <exception cref="ArgumentException">Thrown if public keys and messages do not have
        /// same rank, or public keys or messages is empty.
        /// </exception>
        /// <exception cref="BLSInvalidPublicKeyException">Thrown if length of public key is not
        /// <see cref="PublicKeySize"/> or invalid.
        /// </exception>
        /// <exception cref="BLSInvalidSignatureException">Thrown if length of signature is not
        /// <see cref="SignatureSize"/> or invalid.
        /// </exception>
        /// <returns>Returns <see langword="true"/> if given aggregated signature is valid,
        /// otherwise returns <see langword="false"/>.
        /// </returns>
        public static bool AggregateVerify(byte[] signature, byte[][] publicKeys, byte[][] messages)
        {
            var sig = new BLS.Signature();
            if (publicKeys.Length != messages.Length)
            {
                throw new ArgumentException(
                    "Public keys and messages must have same rank.",
                    $"{nameof(signature)}, {nameof(publicKeys)}");
            }

            if (publicKeys.Length == 0)
            {
                throw new ArgumentException(
                    "Public keys cannot be empty", nameof(publicKeys));
            }

            if (messages.Length == 0)
            {
                throw new ArgumentException(
                    "Messages cannot be empty", nameof(messages));
            }

            var pks = new BLS.PublicKey[publicKeys.Length];
            for (var i = 0; i < publicKeys.Length; i++)
            {
                ValidatePublicKeyInput(publicKeys[i]);
                try
                {
                    pks[i].Deserialize(publicKeys[i]);
                }
                catch (ArithmeticException)
                {
                    throw new BLSInvalidPublicKeyException(
                        $"Invalid public key is in publicKeys " +
                        $"(key: {pks[i].GetHexStr()})");
                }
            }

            BLS.Msg[] msg = new BLS.Msg[messages.Length];
            for (var i = 0; i < messages.Length; i++)
            {
                ValidateMessageInput(messages[i]);
                msg[i].Set(messages[i]);
            }

            ValidateSignatureInput(signature);
            try
            {
                sig.Deserialize(signature);
            }
            catch (ArithmeticException)
            {
                throw new BLSInvalidSignatureException(
                    $"Signature is invalid " +
                    $"(signature: {sig.GetHexStr()})");
            }

            return BLS.AggregateVerify(sig, pks, msg);
        }

        /// <summary>
        /// Verifies multiple messages. Each given public key, signature, and message should be
        /// placed in same order, index-wise.
        /// </summary>
        /// <param name="signatures">A signature to verify.</param>
        /// <param name="publicKeys">A public key used to verify.</param>
        /// <param name="messages">A message used to sign.</param>
        /// <exception cref="ArgumentException">Thrown if any given inputs are empty, or
        /// given message length is not <see cref="MessageSize"/>, or
        /// public keys, signatures, messages do not have same rank.
        /// </exception>
        /// <exception cref="BLSInvalidPublicKeyException">Thrown if length of public key is not
        /// <see cref="PublicKeySize"/> or invalid.
        /// </exception>
        /// <exception cref="BLSInvalidSignatureException">Thrown if length of signature is not
        /// <see cref="SignatureSize"/> or invalid.
        /// </exception>
        /// <returns>Returns <see langword="true"/> if given batch signatures are
        /// <see langword="true"/>, <see langword="false"/> if <i>any</i> signatures is invalid.
        /// </returns>
        public static bool MultiVerify(byte[][] signatures, byte[][] publicKeys, byte[][] messages)
        {
            if (signatures.Length != publicKeys.Length && signatures.Length != messages.Length)
            {
                throw new ArgumentException(
                    "Signatures, public Keys and messages length do not have same rank.",
                    $"{nameof(signatures)}, {nameof(publicKeys)}, {nameof(messages)}");
            }

            if (publicKeys.Length == 0)
            {
                throw new ArgumentException(
                    "Public key must not be empty.", nameof(publicKeys));
            }

            if (signatures.Length == 0)
            {
                throw new ArgumentException(
                    "Signature must not be empty", nameof(signatures));
            }

            if (messages.Length == 0)
            {
                throw new ArgumentException(
                    "Message must not be empty.", nameof(messages));
            }

            var n = signatures.Length;

            var sigs = new BLS.Signature[n];
            var pks = new BLS.PublicKey[n];
            var msgs = new BLS.Msg[n];
            var rands = new BLS.SecretKey[n];

            for (var i = 0; i < signatures.Length; ++i)
            {
                try
                {
                    pks[i].Deserialize(publicKeys[i]);
                }
                catch (ArithmeticException)
                {
                    throw new BLSInvalidPublicKeyException(
                        $"Invalid public key is in publicKeys " +
                        $"(key: {pks[i].GetHexStr()})");
                }

                try
                {
                    sigs[i].Deserialize(signatures[i]);
                }
                catch (ArithmeticException)
                {
                    throw new BLSInvalidSignatureException(
                        $"Invalid signature is in signatures. " +
                        $"(signature: {sigs[i].GetHexStr()})");
                }

                ValidateMessageInput(messages[i]);

                msgs[i].Set(messages[i]);

                _ = BLS.blsSecretKeySetByCSPRNG(ref rands[i]);
            }

            return BLS.MultiVerify(sigs, pks, msgs, rands);
        }

        /// <summary>
        /// Aggregates the given signatures and returns aggregated signature.
        /// </summary>
        /// <param name="lhs">an one signature to aggregate.</param>
        /// <param name="rhs">an other signature to aggregate.</param>
        /// <exception cref="BLSInvalidSignatureException">Thrown if length of signature is not
        /// <see cref="SignatureSize"/> or invalid.
        /// </exception>
        /// <returns>Returns a aggregated signature with given signatures.</returns>
        public static byte[] AggregateSignatures(byte[] lhs, byte[] rhs)
        {
            if (lhs.SequenceEqual(rhs))
            {
                return rhs;
            }

            BLS.Signature rhsSig;
            try
            {
                rhsSig.Deserialize(rhs);
            }
            catch (ArithmeticException)
            {
                throw new BLSInvalidSignatureException(
                    $"Right hand-side signature is invalid. " +
                    $"(signature: {rhsSig.GetHexStr()})");
            }

            BLS.Signature lhsSig;
            try
            {
                lhsSig.Deserialize(lhs);
            }
            catch (ArithmeticException)
            {
                throw new BLSInvalidSignatureException(
                    $"Left hand-side signature is invalid. " +
                    $"(signature: {lhsSig.GetHexStr()})");
            }

            lhsSig.Add(rhsSig);

            return lhsSig.Serialize();
        }

        private static void ValidateSignatureInput(in byte[] signature)
        {
            if (signature.Length != SignatureSize)
            {
                throw new BLSInvalidSignatureException(
                    $"Given signature is not of the correct size. " +
                    $"(expected: {SignatureSize}, actual: {signature.Length})");
            }
        }

        private static void ValidatePrivateKeyInput(in byte[] privateKey)
        {
            BigInteger val = new BigInteger(privateKey);
            if (val.Equals(BigInteger.Zero))
            {
                throw new BLSInvalidPrivateKeyException(
                    "Private key cannot be zero.");
            }

            if (privateKey.Length != PrivateKeySize)
            {
                throw new BLSInvalidPrivateKeyException(
                    $"Given private Key is not of the correct size. " +
                    $"(expected: {PrivateKeySize}, actual: {privateKey.Length})");
            }
        }

        private static void ValidatePublicKeyInput(in byte[] publicKey)
        {
            if (publicKey.Length != PublicKeySize)
            {
                throw new BLSInvalidPublicKeyException(
                    $"Given public Key is not of the correct size. " +
                    $"(expected: {PublicKeySize}, actual: {publicKey.Length})");
            }
        }

        private static void ValidateMessageInput(in byte[] message)
        {
            if (message.Length != MessageSize)
            {
                throw new ArgumentException(
                    $"Given message is not of the correct size. " +
                    $"(expected: {MessageSize}, actual: {message.Length})");
            }
        }
    }
}
