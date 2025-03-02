using CACrypto.Commons;
using CACrypto.VHCA;

namespace CACrypto.RNGValidators;

public static class Program
{
    public static void Main()
    {
        var dataDir = @"D:\PhD_Data";
        var crypto = new VHCAProxy();

        crypto.GenerateBinaryFiles(SampleSize.TenMegaBytes, 1000, dataDir);

        Console.WriteLine("Done!");
    }
}
