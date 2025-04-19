namespace CACrypto.VHCA.Variants;

public class VHCA64Crypto : VHCACryptoBase
{
    public const string Name = "VHCA64";
    public const int DefaultBlockSizeInBytes = 8;

    public VHCA64Crypto() : base(Name, DefaultBlockSizeInBytes) { }
}
