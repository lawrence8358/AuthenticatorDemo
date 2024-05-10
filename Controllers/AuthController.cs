using AuthenticatorDemo.Utility;
using Microsoft.AspNetCore.Mvc;
using OtpNet;

namespace AuthenticatorDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {    
        [HttpGet]
        public FileContentResult Get()
        {
            // ��ȤW�������C��ϥΪ̲��ͤ@���H���� Secret Key�A�ýT�O�w�����x�s�� Secret Key
            var secret = KeyGeneration.GenerateRandomKey();
            var secretKey = Base32Encoding.ToString(secret);
            secretKey = "ZSCMGF6U7H3VYM2QDDU7WNFDFGENTK4K"; // for demo�A�������͵n�J�̪� Secret Key

            var secretData = new OtpAuthDomain(secretKey: secretKey);
            var url = secretData.GenOTPAuthUrl(label: "Lawrence Shen", issuer: "PrimeEagle Studio", secretKey: secretKey);
            byte[] bytes = secretData.GenTotpQRCode(url);

            return File(bytes, "image/png");
        }

        [HttpPost("{code}")]
        public string Post(string code)
        {
            string secretKey = "ZSCMGF6U7H3VYM2QDDU7WNFDFGENTK4K"; // for demo�A�����w���o�n�J�̪� Secret Key

            var secretData = new OtpAuthDomain(secretKey: secretKey);

            return secretData.ValidateTotp(code) ? "���Ҧ��\" : "���ҥ���";
        }
    }
}
