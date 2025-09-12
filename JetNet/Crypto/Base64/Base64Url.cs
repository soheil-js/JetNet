using System.Text;

namespace JetNet.Crypto.Base64
{
    internal static class Base64Url
    {
        public static string Encode(byte[] input)
        {
            string base64 = Convert.ToBase64String(input);
            return base64.Replace("+", "-")
                         .Replace("/", "_")
                         .TrimEnd('=');
        }

        public static byte[] Decode(string input)
        {
            string base64 = input.Replace("-", "+")
                                 .Replace("_", "/");

            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            return Convert.FromBase64String(base64);
        }

        public static string EncodeString(string text)
        {
            return Encode(Encoding.UTF8.GetBytes(text));
        }

        public static string DecodeToString(string encoded)
        {
            return Encoding.UTF8.GetString(Decode(encoded));
        }
    }
}
