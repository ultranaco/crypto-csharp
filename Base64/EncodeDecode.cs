using System;
using System.Text;

namespace Ultranaco.Crypto.Base64
{
  public static class EncodeDecode
  {
    public static string ToBase64(this string input)
    {
      return Convert.ToBase64String(Encoding.UTF8.GetBytes(input));
    }

    public static string DecodeBase64(this string input)
    {
      return Encoding.UTF8.GetString(Convert.FromBase64String(input));
    }
  }
}
