using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace Planetarium.Cryptography.bls.Test
{
    public class Sign
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public Sign(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void SimpleSign()
        {
            SecretKey privateKey;
            privateKey.SetByCSPRNG();

            var publicKey = privateKey.GetPublicKey();
            var message = new byte[] { 0xff, 0xff, 0xff, 0xff };
            var hashedMessage = SHA256.Create().ComputeHash(message);

            var sign = privateKey.Sign(hashedMessage);
            var serializedSign = sign.Serialize();
            Assert.NotNull(serializedSign);

            var verify = publicKey.Verify(sign, hashedMessage);
            Assert.True(verify);
        }

        [Fact]
        public void SimpleSignSerialize()
        {
            SecretKey privateKey;
            privateKey.SetByCSPRNG();

            var message = new byte[] { 0xff, 0xff, 0xff, 0xff };
            var hashedMessage = SHA256.Create().ComputeHash(message);
            var sign = privateKey.Sign(hashedMessage);
            var serializedSign = sign.Serialize();

            Signature testSign;
            testSign.Deserialize(sign.Serialize());

            var unmarshal = testSign.Serialize();
            Assert.Equal(serializedSign, unmarshal);
        }

        [Fact]
        public void DeserializeTest()
        {
            var files = Directory.GetFiles(
                "../../../../tests/deserialization_G2/", "deserialization_succeeds_*");

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = YAMLTestBase.ParseTest(sReader);

                var signature = testYaml.Input["signature"].ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                Signature sig;
                sig.Deserialize(signature);

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
            }
        }

        [Fact]
        public void DeserializeFailingTest()
        {
            var files = Directory.GetFiles(
                "../../../../tests/deserialization_G2/", "deserialization_fails_*");

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = YAMLTestBase.ParseTest(sReader);

                var signature = testYaml.Input["signature"].ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                Signature sig;

                if (signature.Length != BLS.SIGNATURE_SERIALIZE_SIZE)
                {
                    Assert.Throws<ArgumentException>(
                        () => sig.Deserialize(signature));
                }
                else
                {
                    Assert.Throws<ArithmeticException>(() => sig.Deserialize(signature));
                }

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
            }
        }

        [Fact]
        public void AggregateSignTest()
        {
            var files = Directory.GetFiles("../../../../tests/aggregate/");


            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = YAMLTestSingleBase.ParseTest(sReader);

                var signatures = testYaml.Input.Select(x => x.ToBytes()).ToArray();

                var aggSignature = signatures.FirstOrDefault();
                aggSignature ??= new byte[BLS.SIGNATURE_SERIALIZE_SIZE];

                if (signatures.Length == 0)
                {
                    continue;
                }

                Signature aggSig;
                aggSig.Deserialize(aggSignature);

                var expectedSignature = new byte[BLS.SIGNATURE_SERIALIZE_SIZE];

                if (!(testYaml.Output is null))
                {
                    expectedSignature = testYaml.Output.ToBytes();
                }
                var nextSignatures = signatures.Skip(1).ToArray();

                if (signatures.Length == 1)
                {
                    aggSignature = aggSig.Serialize();
                }
                else
                {
                    foreach (var nextSign in nextSignatures)
                    {
                        Signature currSign;
                        currSign.Deserialize(nextSign);
                        aggSig.Add(currSign);
                    }

                    aggSignature = aggSig.Serialize();
                }

                _testOutputHelper.WriteLine("Aggregated Signature: \n" + BitConverter.ToString(aggSignature));
                _testOutputHelper.WriteLine("Expected Signature: \n" + BitConverter.ToString(expectedSignature));
                _testOutputHelper.WriteLine("=====");
                Assert.Equal(expectedSignature, aggSignature);
            }

        }

        [Fact]
        public void SignTest()
        {
            var files = Directory.GetFiles("../../../../tests/sign/");


            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = YAMLTestBase.ParseTest(sReader);

                var privateKey = testYaml.Input["privkey"].ToBytes();
                var message = testYaml.Input["message"].ToBytes();

                SecretKey secretKey;

                if (privateKey.SequenceEqual(new byte[privateKey.Length]))
                {
                    Assert.Throws<ArgumentException>(
                        () => secretKey.Deserialize(privateKey));
                }
                else
                {
                    var expectedSign = testYaml.Output.ToBytes();
                    secretKey.Deserialize(privateKey);

                    var sign = secretKey.Sign(message);
                    var serializedSign = sign.Serialize();

                    _testOutputHelper.WriteLine("Private key: \n" + BitConverter.ToString(privateKey));
                    _testOutputHelper.WriteLine("Message in String: \n" + Encoding.ASCII.GetString(message));
                    _testOutputHelper.WriteLine("Message: \n" + BitConverter.ToString(message));
                    _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(serializedSign));
                    _testOutputHelper.WriteLine("Expected Signature: \n" + BitConverter.ToString(expectedSign));
                    _testOutputHelper.WriteLine("======");
                    Assert.Equal(expectedSign, serializedSign);
                }
            }

        }
    }
}
