using RestSharp;
using System;
using System.Collections.Generic;
using System.Text;
using Falcon.Crypto.SHA256;
using System.Linq;

namespace Ultranaco.Crypto.AWS4
{
  public class AuthorizerBuilder
  {
    private AuthorizerAWS4Request _request;
    private Uri _uri;
    private Method _method;
    private object _payload;
    private DateTime _dateTime;
    private AuthorizerAWS4 _authorizer;
    public AuthorizerBuilder(AuthorizerAWS4Request request)
    {
      _request = request;
    }

    public AuthorizerAWS4 Make(Uri uri, Method method, object payload = null)
    {
      this._uri = uri;
      this._method = method;
      this._payload = payload;
      var credentialScope = string.Format("{0}/{1}/aws4_request", this._request.Region, this._request.Application);
      var dateTime = this._dateTime = DateTime.UtcNow;
      var canonicalhash = this.buildCanonicalHash(uri, method, payload);
      var canonicalParameters = this.signCanonical(canonicalhash);
      var signature = this.getSignatureKey();
      var result = canonicalParameters.HmacSHA256(signature);
      var resultHex = string.Join("", result.Select(b => b.ToString("x2"))).ToLower();
      var authHeader = string.Format("{0} Credential={1}/{2}/{3}, SignedHeaders={4}, Signature={5}", 
        this._request.Algorithm, 
        this._request.Accesskey, dateTime.ToString("yyyyMMdd"), credentialScope, this._request.SignedHeaders, resultHex);

      return this._authorizer = new AuthorizerAWS4
      {
        AuthorizerHeader = authHeader,
        Date = dateTime
      };
    }


    public IRestResponse Execute()
    {
      var restClient = new RestClient(string.Format("{0}://{1}",this._uri.Scheme, this._uri.Host));
      var request = new RestRequest(this._uri.PathAndQuery, this._method);
      request.AddHeader("Authorization", this._authorizer.AuthorizerHeader);
      request.AddHeader("X-Amz-Date", this._dateTime.ToString("yyyyMMddTHHmmssZ"));
      if(this._method == Method.POST || this._method == Method.PUT)
      {
        request.AddJsonBody(this._payload);
      }
      return restClient.Execute(request);
    }

    private string buildCanonicalHash(Uri uri, Method method, object payload)
    {
      var hashPayload = (payload ?? "").Hash256();
      var segments = uri.AbsolutePath.Split("/").Select(s => Uri.EscapeDataString(s));
      var path = string.Join("/", segments);
      var dateTimeISO = this._dateTime.ToString("yyyyMMddTHHmmssZ");

      var url = string.Format(@"{4}
{1}

host:{5}
x-amz-date:{2}

{3}
{0}", hashPayload, path, dateTimeISO, this._request.SignedHeaders, method.ToString(), uri.Host).Replace("\r\n", "\n");
      return url.Hash256();
    }

    public string signCanonical(string canonicalhash)
    {
      var credentialScope = string.Format("{0}/{1}/aws4_request", this._request.Region, this._request.Application);
      var dateLong = this._dateTime.ToString("yyyyMMddTHHmmssZ");
      var date = this._dateTime.ToString("yyyyMMdd");
      var canonicalParametes = string.Format(@"{0}
{1}
{2}/{3}
{4}", this._request.Algorithm, dateLong, date, credentialScope, canonicalhash).Replace("\r\n", "\n");
      return canonicalParametes;
    }
    private byte[] getSignatureKey()
    {
      var dateStamp = this._dateTime.ToString("yyyyMMdd");
      byte[] kSecret = Encoding.UTF8.GetBytes(("AWS4" + this._request.SecretKey).ToCharArray());
      byte[] kDate = dateStamp.HmacSHA256(kSecret);
      byte[] kRegion = this._request.Region.HmacSHA256(kDate);
      byte[] kService = this._request.Application.HmacSHA256(kRegion);
      byte[] kSigning = "aws4_request".HmacSHA256(kService);

      return kSigning;
    }
  }
}
