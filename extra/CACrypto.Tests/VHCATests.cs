using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CACrypto.Tests;

[TestClass]
public class VHCATests : PermutiveCACryptoTestsBase
{
    public VHCATests() : base(new CACrypto.VHCA.VHCAProvider()) { }
}