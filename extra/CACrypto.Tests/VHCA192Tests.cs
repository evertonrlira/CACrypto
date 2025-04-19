using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CACrypto.Tests;

[TestClass]
public class VHCA192Tests : PermutiveCACryptoTestsBase
{
    public VHCA192Tests() : base(new VHCA.Variants.VHCA192Provider()) { }
}