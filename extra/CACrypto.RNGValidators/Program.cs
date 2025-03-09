using CACrypto.Commons;
using CACrypto.HCA;
using CACrypto.RNGValidators.Avalanche;
using CACrypto.RNGValidators.Commons;
using CACrypto.RNGValidators.NIST;
using CACrypto.RNGValidators.PractRand;
using CACrypto.VHCA;

namespace CACrypto.RNGValidators;

public static class Program
{
    public static void Main()
    {
        // var validatorOptions = new ValidatorOptions(SampleSize.TenMegaBytes, 1000, @"D:\PhD_Data");
        // (new NISTValidator(new HCAProvider(), validatorOptions)).Run();
        // (new PractRandValidator(new HCAProvider(), validatorOptions)).Run();
        // (new NISTValidator(new VHCAProvider(), validatorOptions)).Run();
        // (new PractRandValidator(new VHCAProvider(), validatorOptions)).Run();
        IEnumerable<CryptoProviderBase> methodsForAvalanche = [
            new VHCAProvider(),
            new HCAProvider(),
            new AESProvider()
        ];
        (new PlaintextAvalancheValidator(methodsForAvalanche)).Run();
        // (new PlaintextAvalancheValidator(new HCAProvider())).Run();
        // (new PlaintextAvalancheValidator(new VHCAProvider())).Run();
        // (new PlaintextAvalancheValidator(new AESProvider())).Run();

        Console.WriteLine("Done!");
    }
}
