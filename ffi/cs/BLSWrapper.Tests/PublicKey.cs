using System;
using System.IO;
using System.Linq;
using mcl;
using Xunit;
using Xunit.Abstractions;

namespace BLSWrapper.Tests
{
    public class PublicKey
    {
        private ITestOutputHelper _testOutputHelper;

        public PublicKey(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void InvalidPublicKey()
        {
            var publicKey = new byte[BLSWrapper.PublicKeySize - 1];
            publicKey[0] = 1;

            Assert.Throws<BLSInvalidPublicKeyException>(
                () => BLSWrapper.Verify(
                    publicKey,
                    new byte[BLSWrapper.SignatureSize],
                    new byte[BLSWrapper.MessageSize]));

            Assert.Throws<BLSInvalidPublicKeyException>(
                () => BLSWrapper.FastAggregateVerify(
                    new byte[BLSWrapper.SignatureSize],
                    new byte[][] { publicKey },
                    new byte[BLSWrapper.MessageSize]));

            Assert.Throws<BLSInvalidPublicKeyException>(
                () => BLSWrapper.AggregateVerify(
                    new byte[BLSWrapper.SignatureSize],
                    new byte[][] { publicKey },
                    new byte[][] { new byte[BLSWrapper.MessageSize] }));


            Assert.Throws<BLSInvalidPublicKeyException>(
                () => BLSWrapper.MultiVerify(
                    new byte[][] { new byte[BLSWrapper.SignatureSize] },
                    new byte[][] { publicKey },
                    new byte[][] { new byte[BLSWrapper.MessageSize] }));
        }


        [Fact]
        public void Serialize()
        {
            var privateKey = BLSWrapper.GeneratePrivateKey();
            var publicKey = BLSWrapper.GetPublicKey(privateKey);
            Assert.NotNull(publicKey);
            Assert.Equal(BLSWrapper.PublicKeySize, publicKey.Length);
        }

        [Fact]
        public void Deserialize()
        {
            var files = Directory.GetFiles("../../../../tests/deserialization_G1/", "deserialization_succeeds_*");

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = BLSWrapperTestBase.ParseTest(sReader);

                var publicKey = testYaml.Input["pubkey"].ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                BLS.PublicKey pk;
                pk.Deserialize(publicKey);

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(publicKey));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
            }
        }

        [Fact]
        public void DeserializeFailing()
        {
            var files = Directory.GetFiles("../../../../tests/deserialization_G1/", "deserialization_fails_*");

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = BLSWrapperTestBase.ParseTest(sReader);

                var publicKey = testYaml.Input["pubkey"].ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                BLS.PublicKey pk;
                Assert.Throws<ArithmeticException>(
                    () => pk.Deserialize(publicKey));

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(publicKey));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
            }
        }
    }
}
