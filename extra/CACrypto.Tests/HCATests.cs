using CACrypto.HCA;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CACrypto.Tests;

[TestClass]
public class HCATests : PermutiveCACryptoTestsBase
{
    public HCATests() : base(new HCAProvider()) { }
}