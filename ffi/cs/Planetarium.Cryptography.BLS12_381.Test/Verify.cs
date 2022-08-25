using System;
using System.IO;
using System.Linq;
using Xunit;
using Xunit.Abstractions;

namespace Planetarium.Cryptography.BLS12_381.Test
{
    public class Verify
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public Verify(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void MultiVerifyTest()
        {
            var files = Directory.GetFiles("../../../../tests/batch_verify/");
            _testOutputHelper.WriteLine("IsLittleEndian : " + BitConverter.IsLittleEndian);

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                bool result;

                var testYaml = YAMLTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(
                    x =>
                    {
                        PublicKey publicKey;
                        publicKey.Deserialize(x.ToBytes());
                        return publicKey;
                    }).ToArray();
                var messages = testYaml.Input["messages"].Select(
                    x =>
                    {
                        Msg msg;
                        msg.Set(x.ToBytes());
                        return msg;
                    }).ToArray();
                var signatures = testYaml.Input["signatures"].Select(
                    x =>
                    {
                        Signature signature;
                        signature.Deserialize(x.ToBytes());
                        return signature;
                    }).ToArray();
                var expectedResult = bool.Parse(testYaml.Output);

                result = BLS.MultiVerify(signatures, publicKeys, messages);

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk.Serialize()));
                }
                _testOutputHelper.WriteLine("Messages: ");
                foreach (var msg in messages)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(msg.ToByteArray()));
                }
                _testOutputHelper.WriteLine("Signatures: ");
                foreach (var sig in signatures)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(sig.Serialize()));
                }
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
            }
        }

        [Fact]
        public void AggregateVerifyNAPublicKeyTest()
        {
            var files = Directory.GetFiles("../../../../tests/aggregate_verify/", "*_na_pubkeys_*");
            _testOutputHelper.WriteLine("IsLittleEndian : " + BitConverter.IsLittleEndian);

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = YAMLTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(
                    x =>
                    {
                        PublicKey publicKey;
                        publicKey.Deserialize(x.ToBytes());
                        return publicKey;
                    }).ToArray();
                var messages = testYaml.Input["messages"].Select(
                    x =>
                    {
                        Msg msg;
                        msg.Set(x.ToBytes());
                        return msg;
                    }).ToArray();
                var signature = testYaml.Input["signature"].First().ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                Signature sign;

                if (signature.SequenceEqual(new byte[BLS.SIGNATURE_SERIALIZE_SIZE]))
                {
                    Assert.Throws<ArithmeticException>(
                        () => sign.Deserialize(signature));
                }

                Assert.Throws<ArgumentException>(
                    () => sign.AggregateVerify(publicKeys, messages));

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk.Serialize()));
                }
                _testOutputHelper.WriteLine("Messages: ");
                foreach (var msg in messages)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(msg.ToByteArray()));
                }
                _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
            }
        }

        [Fact]
        public void AggregateVerifyTest()
        {
            var files = Directory.GetFiles("../../../../tests/aggregate_verify/");
            _testOutputHelper.WriteLine("IsLittleEndian : " + BitConverter.IsLittleEndian);

            files = files.Where(x => !x.Contains("na_pubkeys")).ToArray();

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                bool result;

                var testYaml = YAMLTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(
                    x =>
                    {
                        PublicKey publicKey;
                        publicKey.Deserialize(x.ToBytes());
                        return publicKey;
                    }).ToArray();
                var messages = testYaml.Input["messages"].Select(
                    x =>
                    {
                        Msg msg;
                        msg.Set(x.ToBytes());
                        return msg;
                    }).ToArray();
                var signature = testYaml.Input["signature"].First().ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                Signature sign;

                if (signature.Length != BLS.SIGNATURE_SERIALIZE_SIZE)
                {
                    Assert.Throws<ArgumentException>(
                        () => sign.Deserialize(signature));
                    result = false;
                }
                else
                {
                    sign.Deserialize(signature);
                    result = sign.AggregateVerify(publicKeys, messages);
                }

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk.Serialize()));
                }
                _testOutputHelper.WriteLine("Messages: ");
                foreach (var msg in messages)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(msg.ToByteArray()));
                }
                _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
            }
        }

        [Fact]
        public void FastAggregateVerifyTest()
        {
            var files = Directory.GetFiles("../../../../tests/fast_aggregate_verify/");
            _testOutputHelper.WriteLine("IsLittleEndian : " + BitConverter.IsLittleEndian);

            files = files.Where(x => !x.Contains("na_pubkeys")).ToArray();

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                bool result;

                var testYaml = YAMLTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(
                    x =>
                    {
                        PublicKey publicKey;
                        publicKey.Deserialize(x.ToBytes());
                        return publicKey;
                    }).ToArray();
                var message = testYaml.Input["message"].First().ToBytes();
                var signature = testYaml.Input["signature"].First().ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                Signature sign;

                if (file.Contains("fast_aggregate_verify_tampered_signature"))
                {
                    Assert.Throws<ArithmeticException>(
                        () => sign.Deserialize(signature));
                    result = false;
                }
                else
                {
                    Msg msg;
                    msg.Set(message);
                    sign.Deserialize(signature);
                    result = sign.FastAggregateVerify(publicKeys, msg);
                }

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk.Serialize()));
                }
                _testOutputHelper.WriteLine("Message: \n" + BitConverter.ToString(message));
                _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
            }
        }

        [Fact]
        public void FastAggregateVerifyNAPublicKeyTest()
        {
            var files = Directory.GetFiles("../../../../tests/fast_aggregate_verify/", "*_na_pubkeys_*");
            _testOutputHelper.WriteLine("IsLittleEndian : " + BitConverter.IsLittleEndian);

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = YAMLTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(
                    x =>
                    {
                        PublicKey publicKey;
                        publicKey.Deserialize(x.ToBytes());
                        return publicKey;
                    }).ToArray();
                var message = testYaml.Input["message"].First().ToBytes();
                var signature = testYaml.Input["signature"].First().ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                Signature sign;
                if (signature.SequenceEqual(new byte[BLS.SIGNATURE_SERIALIZE_SIZE]))
                {
                    Assert.Throws<ArithmeticException>(
                        () => sign.Deserialize(signature));
                }
                else
                {
                    Msg msg;
                    msg.Set(message);
                    sign.Deserialize(signature);

                    Assert.Throws<ArgumentException>(
                        () => sign.FastAggregateVerify(publicKeys, msg));
                }

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk.Serialize()));
                }
                _testOutputHelper.WriteLine("Message: \n" + BitConverter.ToString(message));
                _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
            }
        }

        [Fact]
        public void VerifyTest()
        {
            var files = Directory.GetFiles("../../../../tests/verify/");


            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = YAMLTestBase.ParseTest(sReader);

                var publicKey = testYaml.Input["pubkey"].ToBytes();
                var message = testYaml.Input["message"].ToBytes();
                var signature = testYaml.Input["signature"].ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);
                bool result;

                PublicKey pk;
                Signature sign;

                pk.Deserialize(publicKey);

                if (file.Contains("verify_tampered_signature_case"))
                {
                    Assert.Throws<ArithmeticException>(
                        () => sign.Deserialize(signature));
                    result = false;
                }
                else
                {
                    Msg msg;
                    msg.Set(message);
                    sign.Deserialize(signature);
                    result = pk.Verify(sign, msg);
                }

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(publicKey));
                _testOutputHelper.WriteLine("Message: \n" + BitConverter.ToString(message));
                _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
            }
        }
    }
}
