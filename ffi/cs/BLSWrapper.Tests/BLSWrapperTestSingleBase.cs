using System.Collections.Generic;
using System.IO;
using mcl;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace BLSWrapper.Tests
{
    public sealed class BLSWrapperTestSingleBase
    {
        public List<string> Input { get; set; }

        public string Output { get; set; }

        public static BLSWrapperTestSingleBase ParseTest(StreamReader yaml)
        {
            var deserializer = new DeserializerBuilder().
                WithNamingConvention(CamelCaseNamingConvention.Instance).
                Build();
            return deserializer.Deserialize<BLSWrapperTestSingleBase>(yaml);
        }
    }
}
