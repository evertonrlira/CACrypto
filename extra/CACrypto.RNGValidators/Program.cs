using CACrypto.Commons;
using CACrypto.RNGValidators.Commons;
using CACrypto.VHCA.Variants;

namespace CACrypto.RNGValidators;

public static class Program
{
    public static void Main()
    {
        IEnumerable<CryptoProviderBase> methodsForAvalanche = [
            // new VHCAProvider(),
            // new HCAProvider(),
            // new AESProvider()
            new VHCA64Provider(),
        ];
        // (new Avalanche.PlaintextAvalancheValidator(methodsForAvalanche)).Run();
        // (new Avalanche.KeyAvalancheValidator(methodsForAvalanche)).Run();

        var validatorOptions = new ValidatorOptions(SampleSize.TenMegaBytes, 1000, @"D:\PhD_Data");
        // (new NIST.NISTValidator(new AESProvider(), validatorOptions)).Run();
        // (new NIST.NISTValidator(new HCAProvider(), validatorOptions)).Run();
        // (new NIST.NISTValidator(new VHCAProvider(), validatorOptions)).Run();
        (new NIST.NISTValidator(new VHCA64Provider(), validatorOptions)).Run();
        // (new NIST.NISTValidator(new VHCA192Provider(), validatorOptions)).Run();
        // (new NIST.NISTValidator(new VHCA256Provider(), validatorOptions)).Run();
        // (new PractRand.PractRandValidator(new AESProvider(), validatorOptions)).Run();
        // (new PractRand.PractRandValidator(new HCAProvider(), validatorOptions)).Run();
        // (new PractRand.PractRandValidator(new VHCAProvider(), validatorOptions)).Run();
        (new PractRand.PractRandValidator(new VHCA64Provider(), validatorOptions)).Run();
        // (new PractRand.PractRandValidator(new VHCA192Provider(), validatorOptions)).Run();
        // (new PractRand.PractRandValidator(new VHCA256Provider(), validatorOptions)).Run();

        Console.WriteLine("Done!");
    }
}
