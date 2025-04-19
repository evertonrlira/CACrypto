namespace CACrypto.VHCA.Variants;

public class VHCA256Provider : VHCAProvider
{
    public VHCA256Provider() : base(new VHCA256Crypto()) { }
}
