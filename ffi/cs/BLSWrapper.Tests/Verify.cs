using System;
using System.IO;
using System.Linq;
using System.Text;
using BLSWrapper.Tests;
using Xunit;
using Xunit.Abstractions;

namespace BLSWrapper.Tests
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

                var testYaml = BLSWrapperTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(x => x.ToBytes()).ToArray();
                var messages = testYaml.Input["messages"].Select(x => x.ToBytes()).ToArray();
                var signatures = testYaml.Input["signatures"].Select(x => x.ToBytes()).ToArray();
                var expectedResult = bool.Parse(testYaml.Output);

                result = BLSWrapper.MultiVerify(signatures, publicKeys, messages);

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk));
                }
                _testOutputHelper.WriteLine("Messages: ");
                foreach (var msg in messages)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(msg));
                }
                _testOutputHelper.WriteLine("Signatures: ");
                foreach (var sig in signatures)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(sig));
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
                bool result;

                var testYaml = BLSWrapperTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(x => x.ToBytes()).ToArray();
                var messages = testYaml.Input["messages"].Select(x => x.ToBytes()).ToArray();
                var signature = testYaml.Input["signature"].First().ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                Assert.Throws<ArgumentException>(
                    () => BLSWrapper.AggregateVerify(signature, publicKeys, messages));
                result = false;

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk));
                }
                _testOutputHelper.WriteLine("Messages: ");
                foreach (var msg in messages)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(msg));
                }
                _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
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

                var testYaml = BLSWrapperTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(x => x.ToBytes()).ToArray();
                var messages = testYaml.Input["messages"].Select(x => x.ToBytes()).ToArray();
                var signature = testYaml.Input["signature"].First().ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                if (signature.Length != BLSWrapper.SignatureSize)
                {
                    Assert.Throws<BLSInvalidSignatureException>(
                        () => BLSWrapper.AggregateVerify(signature, publicKeys, messages));
                    result = false;
                }
                else
                {
                    result = BLSWrapper.AggregateVerify(signature, publicKeys, messages);
                }

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk));
                }
                _testOutputHelper.WriteLine("Messages: ");
                foreach (var msg in messages)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(msg));
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

                var testYaml = BLSWrapperTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(x => x.ToBytes()).ToArray();
                var message = testYaml.Input["message"].First().ToBytes();
                var signature = testYaml.Input["signature"].First().ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                if (file.EndsWith("fast_aggregate_verify_tampered_signature_3d7576f3c0e3570a.yaml") ||
                    file.EndsWith("fast_aggregate_verify_tampered_signature_652ce62f09290811.yaml"))
                {
                    Assert.Throws<BLSInvalidSignatureException>(
                        () => BLSWrapper.FastAggregateVerify(signature, publicKeys, message));
                    result = false;
                }
                else
                {
                    result = BLSWrapper.FastAggregateVerify(signature, publicKeys, message);
                }

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk));
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

                var testYaml = BLSWrapperTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(x => x.ToBytes()).ToArray();
                var message = testYaml.Input["message"].First().ToBytes();
                var signature = testYaml.Input["signature"].First().ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                Assert.Throws<ArgumentException>(
                    () => BLSWrapper.FastAggregateVerify(signature, publicKeys, message));

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk));
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

                var testYaml = BLSWrapperTestBase.ParseTest(sReader);

                var publicKey = testYaml.Input["pubkey"].ToBytes();
                var message = testYaml.Input["message"].ToBytes();
                var signature = testYaml.Input["signature"].ToBytes();
                var expectedResult = bool.Parse(testYaml.Output);

                var result = BLSWrapper.Verify(publicKey, signature, message);

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
