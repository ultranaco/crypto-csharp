using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Ultranaco.Crypto.SHA256
{
  public static class ObjectHash256Extend
  {
    public static string Hash256(this object obj)
    {
      var objStr = string.Empty;
      if (!(obj is string))
        objStr = JsonConvert.SerializeObject(obj);
      else
        objStr = (string)obj;

      string hashString;
      using (var hasher = new SHA256Managed())
      {
        var hash = hasher.ComputeHash(Encoding.UTF8.GetBytes(objStr));
        hashString = string.Join("", hash.Select(b => b.ToString("x2")).ToArray()).ToLower();
      }

      return hashString;
    }

    public static byte[] HmacSHA256(this string data, byte[] key)
    {
      string algorithm = "HmacSHA256";
      byte[] bytes;
      using (KeyedHashAlgorithm kha = KeyedHashAlgorithm.Create(algorithm))
      {
        kha.Key = key;
        bytes = kha.ComputeHash(Encoding.UTF8.GetBytes(data));
      }
      return bytes;
    }
  }
}
