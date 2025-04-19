namespace CACrypto.VHCA.Variants;

public class VHCA256Crypto : VHCACrypto
{
    public new const string Name = "VHCA256";
    public new const int KeySizeInBytes = 96;
    public new const int DefaultBlockSizeInBytes = 32;
    public new const int DefaultBlockSizeInBits = 256;
}
