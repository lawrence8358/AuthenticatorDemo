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
            // 實務上必須為每位使用者產生一組隨機的 Secret Key，並確保安全的儲存此 Secret Key
            var secret = KeyGeneration.GenerateRandomKey();
            var secretKey = Base32Encoding.ToString(secret);
            secretKey = "ZSCMGF6U7H3VYM2QDDU7WNFDFGENTK4K"; // for demo，模擬產生登入者的 Secret Key

            var secretData = new OtpAuthDomain(secretKey: secretKey);
            var url = secretData.GenOTPAuthUrl(label: "Lawrence Shen", issuer: "PrimeEagle Studio", secretKey: secretKey);
            byte[] bytes = secretData.GenTotpQRCode(url);

            return File(bytes, "image/png");
        }

        [HttpPost("{code}")]
        public string Post(string code)
        {
            string secretKey = "ZSCMGF6U7H3VYM2QDDU7WNFDFGENTK4K"; // for demo，模擬已取得登入者的 Secret Key

            var secretData = new OtpAuthDomain(secretKey: secretKey);

            return secretData.ValidateTotp(code) ? "驗證成功" : "驗證失敗";
        }
    }
}
