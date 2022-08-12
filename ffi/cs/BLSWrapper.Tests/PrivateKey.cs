using System;
using System.IO;
using System.Linq;
using mcl;
using Xunit;
using Xunit.Abstractions;

namespace BLSWrapper.Tests
{
    public class PrivateKey
    {
        private ITestOutputHelper _testOutputHelper;

        public PrivateKey(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void InvalidLengthPrivateKey()
        {
            var privateKey = new byte[BLSWrapper.PrivateKeySize - 1];
            privateKey[0] = 1;
            BLS.SecretKey sk;

            Assert.Throws<ArithmeticException>(
                () => sk.Deserialize(privateKey));
        }

        [Fact]
        public void LoadTestSuitePrivateKeys()
        {
            var files = Directory.GetFiles("../../../../tests/sign/");


            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);

                var testYaml = BLSWrapperTestBase.ParseTest(sReader);
                byte[] privateKey = new byte[]{ 0x00, };
                BLS.SecretKey sk;

                // MCL follows the system endianess, and test suite uses big endian.
                privateKey = testYaml.Input["privkey"].ToBytes();

                sk.Deserialize(privateKey);
                _testOutputHelper.WriteLine("Private key: " + BitConverter.ToString(privateKey));
                _testOutputHelper.WriteLine("=====");
            }
        }
    }
}
