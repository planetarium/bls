using System;
using System.IO;
using System.Linq;
using Xunit;
using Xunit.Abstractions;

namespace Planetarium.Cryptography.BLS12_381.Test
{
    public class PrivateKeyTest
    {
        private ITestOutputHelper _testOutputHelper;

        public PrivateKeyTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void InvalidLengthPrivateKey()
        {
            var privateKey = new byte[BLS.SECRETKEY_SERIALIZE_SIZE - 1];
            privateKey[0] = 1;
            SecretKey sk;

            Assert.Throws<ArgumentException>(() => sk.Deserialize(privateKey));
        }

        [Fact]
        public void LoadTestSuitePrivateKeys()
        {
            var files = Directory.GetFiles(
                "../../../tests/sign/").Except(
                new[] { "../../../tests/sign/sign_case_zero_privkey.yaml" });

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = YAMLTestBase.ParseTest(sReader);
                byte[] privateKey = new byte[]{ 0x00, };
                SecretKey sk;

                // MCL follows the system endianess, and test suite uses big endian.
                privateKey = testYaml.Input["privkey"].ToBytes();

                sk.Deserialize(privateKey);
                _testOutputHelper.WriteLine("Private key: " + BitConverter.ToString(privateKey));
                _testOutputHelper.WriteLine("=====");
            }
        }
    }
}
