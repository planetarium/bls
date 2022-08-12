using System.Collections.Generic;
using System.IO;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace bls.Test
{
    public sealed class YAMLTestBase
    {
        public Dictionary<string, string> Input { get; set; }

        public string Output { get; set; }

        public static YAMLTestBase ParseTest(StreamReader yaml)
        {
            var deserializer = new DeserializerBuilder().
                WithNamingConvention(CamelCaseNamingConvention.Instance).
                Build();
            return deserializer.Deserialize<YAMLTestBase>(yaml);
        }
    }
}
