using System.Collections.Generic;
using System.IO;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace bls.Test
{
    public sealed class YAMLTestSingleBase
    {
        public List<string> Input { get; set; }

        public string Output { get; set; }

        public static YAMLTestSingleBase ParseTest(StreamReader yaml)
        {
            var deserializer = new DeserializerBuilder().
                WithNamingConvention(CamelCaseNamingConvention.Instance).
                Build();
            return deserializer.Deserialize<YAMLTestSingleBase>(yaml);
        }
    }
}
