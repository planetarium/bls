using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using BLSWrapper.Tests;
using mcl;
using Xunit;
using Xunit.Abstractions;

namespace BLSWrapper.Tests
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
            var privateKey = BLSWrapper.GeneratePrivateKey();
            var publicKey = BLSWrapper.GetPublicKey(privateKey);
            var message = new byte[] { 0xff, 0xff, 0xff, 0xff };
            var hashedMessage = SHA256.Create().ComputeHash(message);

            var sign = BLSWrapper.Sign(privateKey, hashedMessage);
            Assert.NotNull(sign);
            var verify = BLSWrapper.Verify(publicKey, sign, hashedMessage);
            Assert.True(verify);
        }

        [Fact]
        public void SimpleSignSerialize()
        {
            var privateKey = BLSWrapper.GeneratePrivateKey();
            var message = new byte[] { 0xff, 0xff, 0xff, 0xff };
            var hashedMessage = SHA256.Create().ComputeHash(message);
            var sign = BLSWrapper.Sign(privateKey, hashedMessage);

            BLS.Signature sig;

            sig.Deserialize(sign);
            var unmarshal = sig.Serialize().ToArray();
            Assert.Equal(sign, unmarshal);
        }

        [Fact]
        public void DeserializeTest()
        {
            var files = Directory.GetFiles("../../../../tests/deserialization_G2/", "deserialization_succeeds_*");

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = BLSWrapperTestBase.ParseTest(sReader);

                var signature = testYaml.Input["signature"].ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                BLS.Signature sig;
                sig.Deserialize(signature);

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
            }
        }

        [Fact]
        public void DeserializeFailingTest()
        {
            var files = Directory.GetFiles("../../../../tests/deserialization_G2/", "deserialization_fails_*");

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = BLSWrapperTestBase.ParseTest(sReader);

                var signature = testYaml.Input["signature"].ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                BLS.Signature sig;
                Assert.Throws<ArithmeticException>(() => sig.Deserialize(signature));

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

                var testYaml = BLSWrapperTestSingleBase.ParseTest(sReader);

                var signatures = testYaml.Input.Select(x => x.ToBytes()).ToArray();

                var aggSignature = signatures.FirstOrDefault();
                aggSignature ??= new byte[BLSWrapper.SignatureSize];

                var expectedSignature = new byte[BLSWrapper.SignatureSize];

                if (!(testYaml.Output is null))
                {
                    expectedSignature = testYaml.Output.ToBytes();
                }
                var nextSignatures = signatures.Skip(1).ToArray();

                if (signatures.Length == 1)
                {
                    aggSignature = BLSWrapper.AggregateSignatures(aggSignature, aggSignature);
                }
                else
                {
                    foreach (var nextSign in nextSignatures)
                    {
                        aggSignature = BLSWrapper.AggregateSignatures(aggSignature, nextSign);
                    }
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

                var testYaml = BLSWrapperTestBase.ParseTest(sReader);

                var privateKey = testYaml.Input["privkey"].ToBytes();
                var message = testYaml.Input["message"].ToBytes();

                if (privateKey.SequenceEqual(new byte[privateKey.Length]))
                {
                    Assert.Throws<BLSInvalidPrivateKeyException>(
                        () => BLSWrapper.Sign(privateKey, message));
                }
                else
                {
                    var expectedSign = testYaml.Output.ToBytes();

                    var sign = BLSWrapper.Sign(privateKey, message);

                    _testOutputHelper.WriteLine("Private key: \n" + BitConverter.ToString(privateKey));
                    _testOutputHelper.WriteLine("Message in String: \n" + Encoding.ASCII.GetString(message));
                    _testOutputHelper.WriteLine("Message: \n" + BitConverter.ToString(message));
                    _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(sign));
                    _testOutputHelper.WriteLine("Expected Signature: \n" + BitConverter.ToString(expectedSign));
                    _testOutputHelper.WriteLine("======");
                    Assert.Equal(expectedSign, sign);
                }
            }

        }
    }
}
