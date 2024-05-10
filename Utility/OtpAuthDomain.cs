using OtpNet;
using QRCoder;

namespace AuthenticatorDemo.Utility;

public class OtpAuthDomain
{
    #region Members 

    private Totp? _totp = null;

    #endregion

    #region Properties  

    public string SecretKey { get; }

    #endregion

    #region Constructors

    public OtpAuthDomain(string secretKey)
    {
        SecretKey = secretKey;
    }

    #endregion

    #region Methods

    public string GenOTPAuthUrl(string label, string issuer, string secretKey, int period = 30, int digits = 6)
    {
        var url = new OtpUri(OtpType.Totp, secretKey,
            user: label,
            issuer: issuer,
            digits: digits,
            period: period
        ).ToString();

        // 會產生以下格式的字串
        // otpauth://totp/PrimeEagle%20Studio:Lawrence%20Shen?secret=ZSCMGF6U7H3VYM2QDDU7WNFDFGENTK4K&issuer=PrimeEagle%20Studio&algorithm=SHA1&digits=6&period=30

        return url;
    }

    public byte[] GenTotpQRCode(string url)
    {
        using QRCodeGenerator qRCodeGenerator = new QRCodeGenerator();
        using QRCodeData data = qRCodeGenerator.CreateQrCode(url, QRCodeGenerator.ECCLevel.Q);
        using PngByteQRCode qRCode = new PngByteQRCode(data);
        byte[] image = qRCode.GetGraphic(10);

        return image;
    }

    public bool ValidateTotp(string code, int period = 30, int digits = 6)
    {
        if (_totp == null)
            _totp = new Totp(Base32Encoding.ToBytes(SecretKey), step: period, totpSize: digits);

        if (_totp.VerifyTotp(code, out var timeStepMatched))
        {
            // 實務上，驗證成功後，可以將 timeStepMatched 存入資料庫，
            // 若時間已存在，代表 QR Code 已經被使用過，避免重複使用
            return true;
        }

        return false;
    }

    #endregion
}
