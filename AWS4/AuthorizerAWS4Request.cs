using System;
using System.Collections.Generic;
using System.Text;

namespace Ultranaco.Crypto.AWS4
{
  public class AuthorizerAWS4Request
  {
    public string Region { get; set; }
    public string Algorithm { get; set; }
    public string Application { get; set; }
    public string SignedHeaders { get; set; }
    public string Accesskey { get; set; }
    public string SecretKey { get; set; }
  }
}
