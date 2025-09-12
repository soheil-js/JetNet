using JetNet.Models.Params;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JetNet.Models.Converter
{
    internal class ParamsConverter : JsonConverter<IKdfParams>
    {
        public override void WriteJson(JsonWriter writer, IKdfParams value, JsonSerializer serializer)
        {
            serializer.Serialize(writer, value);
        }

        public override IKdfParams ReadJson(JsonReader reader, Type objectType, IKdfParams existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            var obj = JObject.Load(reader);
            var type = obj["type"]?.ToString() ?? throw new Exception("KDF type missing");

            return type switch
            {
                "Argon2id" => obj.ToObject<Argon2Params>(),
                "Scrypt" => obj.ToObject<ScryptParams>(),
                _ => throw new Exception($"Unsupported KDF type: {type}")
            };
        }
    }
}
