using System.Collections.Generic;
using System.IO;
using mcl;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace BLSWrapper.Tests
{
    public sealed class BLSWrapperTestListBase
    {
        public Dictionary<string, List<string>> Input { get; set; }

        public string Output { get; set; }

        public static BLSWrapperTestListBase ParseTest(StreamReader yaml)
        {
            var deserializer = new DeserializerBuilder().
                WithNamingConvention(CamelCaseNamingConvention.Instance).
                Build();
            return deserializer.Deserialize<BLSWrapperTestListBase>(yaml);
        }
    }
}
