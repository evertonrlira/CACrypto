namespace CACrypto.VHCA.Variants;

public class VHCA192Crypto : VHCACryptoBase
{
    public const string Name = "VHCA192";
    public const int DefaultBlockSizeInBytes = 24;

    public VHCA192Crypto() : base(Name, DefaultBlockSizeInBytes) { }
}
