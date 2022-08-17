using System;
using System.IO;
using bls;
using Xunit;
using Xunit.Abstractions;

namespace bls.Test
{
    public class PublicKeyTest
    {
        private ITestOutputHelper _testOutputHelper;

        public PublicKeyTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }


        [Fact]
        public void SerializeTest()
        {
            SecretKey privateKey;
            privateKey.SetByCSPRNG();

            var publicKey = privateKey.GetPublicKey();
            var deserializedPublicKey = publicKey.Serialize();
            Assert.NotNull(deserializedPublicKey);
            Assert.Equal(BLS.PUBLICKEY_SERIALIZE_SIZE, deserializedPublicKey.Length);
        }

        [Fact]
        public void DeserializeTest()
        {
            var files = Directory.GetFiles(
                "../../../../tests/deserialization_G1/", "deserialization_succeeds_*");

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = YAMLTestBase.ParseTest(sReader);

                var publicKey = testYaml.Input["pubkey"].ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                PublicKey pk;
                pk.Deserialize(publicKey);

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(publicKey));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
            }
        }

        [Fact]
        public void DeserializeFailing()
        {
            var files = Directory.GetFiles(
                "../../../../tests/deserialization_G1/", "deserialization_fails_*");

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = YAMLTestBase.ParseTest(sReader);

                var publicKey = testYaml.Input["pubkey"].ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                PublicKey pk;
                if (publicKey.Length != BLS.PUBLICKEY_SERIALIZE_SIZE)
                {
                    Assert.Throws<ArgumentException>(() => pk.Deserialize(publicKey));
                }
                else
                {
                    Assert.Throws<ArithmeticException>(() => pk.Deserialize(publicKey));
                }

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(publicKey));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
            }
        }
    }
}
