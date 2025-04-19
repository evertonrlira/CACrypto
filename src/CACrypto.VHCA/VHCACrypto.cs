namespace CACrypto.VHCA;

public class VHCACrypto : VHCACryptoBase
{
    public const string Name = "VHCA";
    public const int DefaultBlockSizeInBytes = 16;

    public VHCACrypto() : base(Name, DefaultBlockSizeInBytes) { }
}
