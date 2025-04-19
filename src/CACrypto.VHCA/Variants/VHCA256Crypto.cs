namespace CACrypto.VHCA.Variants;

public class VHCA256Crypto : VHCACryptoBase
{
    public const string Name = "VHCA256";
    public const int DefaultBlockSizeInBytes = 32;

    public VHCA256Crypto() : base(Name, DefaultBlockSizeInBytes) { }
}
