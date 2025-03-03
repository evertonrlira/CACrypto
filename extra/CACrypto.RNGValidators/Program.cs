using CACrypto.Commons;
using CACrypto.HCA;
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
        // (new NISTValidator(new HCAProxy(), validatorOptions)).Run();
        // (new PractRandValidator(new HCAProxy(), validatorOptions)).Run();
        // (new NISTValidator(new VHCAProxy(), validatorOptions)).Run();
        // (new PractRandValidator(new VHCAProxy(), validatorOptions)).Run();

        Console.WriteLine("Done!");
    }
}
