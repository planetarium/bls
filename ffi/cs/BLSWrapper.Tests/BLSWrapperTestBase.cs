using System.Collections.Generic;
using System.IO;
using mcl;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace BLSWrapper.Tests
{
    public sealed class BLSWrapperTestBase
    {
        public Dictionary<string, string> Input { get; set; }

        public string Output { get; set; }

        public static BLSWrapperTestBase ParseTest(StreamReader yaml)
        {
            var deserializer = new DeserializerBuilder().
                WithNamingConvention(CamelCaseNamingConvention.Instance).
                Build();
            return deserializer.Deserialize<BLSWrapperTestBase>(yaml);
        }
    }
}
