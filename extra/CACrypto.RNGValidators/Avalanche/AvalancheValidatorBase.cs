using CACrypto.Commons;
using CACrypto.RNGValidators.Commons;
using System.Collections.Concurrent;
using System.Text;

namespace CACrypto.RNGValidators.Avalanche;

internal abstract class AvalancheValidatorBase(IEnumerable<CryptoProviderBase> cryptoMethods, ValidatorOptions? opt)
    : CryptoValidatorBase(cryptoMethods, opt)
{
    protected override string CompileValidationReport(CryptoProviderBase cryptoMethod)
    {
        var plaintextSet = Util.GetSecureRandomByteArrays(Options.InputSampleSize, Options.InputSamplesCount);

        var disturbanceSet = new ConcurrentBag<byte[]>();
        Parallel.ForEach(plaintextSet, originalPlaintext =>
        {
            var originalKey = cryptoMethod.GenerateRandomKey();
            var originalCiphertext = cryptoMethod.EncryptAsSingleBlock(originalPlaintext, originalKey);
            var nextPlaintext = GetNextPlaintext(originalPlaintext);
            var nextKey = GetNextKey(originalKey);
            var disturbedCiphertext = cryptoMethod.EncryptAsSingleBlock(nextPlaintext, nextKey);
            var disturbance = Util.XOR(originalCiphertext, disturbedCiphertext);
            disturbanceSet.Add(disturbance);
        });
        return CompileValidationReport(cryptoMethod, disturbanceSet);
    }

    protected abstract CryptoKey GetNextKey(CryptoKey originalKey);
    protected abstract byte[] GetNextPlaintext(byte[] originalPlaintext);

    private string CompileValidationReport(CryptoProviderBase cryptoMethod, IEnumerable<byte[]> disturbanceResults)
    {
        var culture = System.Globalization.CultureInfo.CreateSpecificCulture("en-US");

        var reportCompiler = new StringBuilder();
        reportCompiler.AppendLine($"METHOD {cryptoMethod.GetMethodName()}");
        reportCompiler.AppendLine($"SUCCESS RATES ON {GetValidatorName()}");
        reportCompiler.AppendLine($"INPUT COUNT: {disturbanceResults.Count()}");

        var sequenceLengthInBits = 8 * disturbanceResults.First().Length;

        double avgBitsSum = 0.0D, avgBitsStdDevSum = 0.0D, entrophyMinSum = 0.0D, entrophyMaxSum = 0.0D, entrophyAvgSum = 0.0D, entrophyStdDevSum = 0.0D;

        var distribution = disturbanceResults.Select(Z => (float)Util.CountBits(Z) * 100.0F / (float)sequenceLengthInBits);

        var avgBits = distribution.Average(); avgBitsSum += avgBits;
        reportCompiler.AppendLine($"DISTURBED BITS PCT (AVG): {avgBits.ToString("N3", culture.NumberFormat)}");
        var avgBitsStdDev = Util.PopulationStandardDeviation(distribution); avgBitsStdDevSum += avgBitsStdDev;
        reportCompiler.AppendLine($"DISTURBED BITS PCT (STD DEV): {avgBitsStdDev.ToString("N3", culture.NumberFormat)}");

        var entrophySet = disturbanceResults.Select(Z => Util.SpatialEntropyCalculusForBinary(Util.ByteArrayToBinaryArray(Z)));

        var entrophyMin = entrophySet.Min(); entrophyMinSum += entrophyMin;
        reportCompiler.AppendLine($"ENTROPY MIN: {entrophyMin.ToString("N3", culture.NumberFormat)}");
        var entrophyMax = entrophySet.Max(); entrophyMaxSum += entrophyMax;
        reportCompiler.AppendLine($"ENTROPY MAX: {entrophyMax.ToString("N3", culture.NumberFormat)}");
        var entrophyAvg = entrophySet.Average(); entrophyAvgSum += entrophyAvg;
        reportCompiler.AppendLine($"ENTROPY AVG: {entrophyAvg.ToString("N3", culture.NumberFormat)}");
        var entrophyStdDev = Util.PopulationStandardDeviation(entrophySet); entrophyStdDevSum += entrophyStdDev;
        reportCompiler.AppendLine($"ENTROPY STD DEV: {entrophyStdDev.ToString("N3", culture.NumberFormat)}");

        return reportCompiler.ToString();
    }

    protected override int GetMaxAllowedDegreeOfParallelism()
    {
        return Environment.ProcessorCount;
    }

    protected override ValidatorOptions GetDefaultValidatorOptions()
    {
        return new ValidatorOptions
        {
            InputSampleSize = SampleSize.DefaultBlockSize,
            InputSamplesCount = (8 * SampleSize.DefaultBlockSize) * (8 * SampleSize.DefaultBlockSize)
        };
    }
}
