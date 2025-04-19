using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CACrypto.Tests;

[TestClass]
public class VHCA256Tests : PermutiveCACryptoTestsBase
{
    public VHCA256Tests() : base(new VHCA.Variants.VHCA256Provider()) { }
}