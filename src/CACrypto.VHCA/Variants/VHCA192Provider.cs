namespace CACrypto.VHCA.Variants;

public class VHCA192Provider : VHCAProvider
{
    public VHCA192Provider() : base(new VHCA192Crypto()) { }
}
