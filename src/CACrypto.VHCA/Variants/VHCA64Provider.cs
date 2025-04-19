namespace CACrypto.VHCA.Variants;

public class VHCA64Provider : VHCAProvider
{
    public VHCA64Provider() : base(new VHCA64Crypto()) { }
}
