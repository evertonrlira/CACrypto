using CACrypto.Commons;
using CACrypto.RNGValidators.Commons;
using System.Buffers;
using System.Collections.Concurrent;
using System.Text;

namespace CACrypto.RNGValidators.Avalanche;

internal abstract class AvalancheValidatorBase(IEnumerable<CryptoProviderBase> cryptoMethods, ValidatorOptions? opt)
    : CryptoValidatorBase(cryptoMethods, opt)
{
    protected override string CompileValidationReport(CryptoProviderBase cryptoMethod)
    {
        var blockSize = Options.InputSampleSize;
        var randomPlaintextSet = Util.GetSecureRandomByteArrays(blockSize, Options.InputSamplesCount);
        var preparedPlaintextSet = Util.GetLowEntropyByteArrays(blockSize, Options.InputSamplesCount);
        IEnumerable<byte[]> plaintextSet = [..randomPlaintextSet, ..preparedPlaintextSet];

        var disturbanceSet = new ConcurrentBag<byte[]>();
        Parallel.ForEach(plaintextSet, originalPlaintext =>
        {
            var originalCiphertext = new byte[blockSize];
            var disturbedCiphertext = new byte[blockSize];

            var originalKey = cryptoMethod.GenerateRandomKey();
            cryptoMethod.EncryptAsSingleBlock(originalPlaintext, originalKey, originalCiphertext, blockSize);
            var nextPlaintext = GetNextPlaintext(originalPlaintext);
            var nextKey = GetNextKey(originalKey);
            cryptoMethod.EncryptAsSingleBlock(nextPlaintext, nextKey, disturbedCiphertext, blockSize);
            var disturbance = Util.XOR(originalCiphertext, disturbedCiphertext, blockSize);
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

        reportCompiler.AppendLine($"DISTURBED BITS PCT (MIN): {distribution.Min().ToString("N3", culture.NumberFormat)}");
        reportCompiler.AppendLine($"DISTURBED BITS PCT (MAX): {distribution.Max().ToString("N3", culture.NumberFormat)}");
        var avgBits = distribution.Average(); avgBitsSum += avgBits;
        reportCompiler.AppendLine($"DISTURBED BITS PCT (AVG): {avgBits.ToString("N3", culture.NumberFormat)}");
        var avgBitsStdDev = Util.PopulationStandardDeviation(distribution); avgBitsStdDevSum += avgBitsStdDev;
        reportCompiler.AppendLine($"DISTURBED BITS PCT (STD DEV): {avgBitsStdDev.ToString("N3", culture.NumberFormat)}");

        var entropySet = new List<float>();
        foreach (var disturbanceArrayBytes in disturbanceResults)
        {
            var disturbanceArrayBits = ArrayPool<int>.Shared.Rent(sequenceLengthInBits);
            Util.ByteArrayToBinaryArray(disturbanceArrayBytes, disturbanceArrayBits);
            var entropy = Util.SpatialEntropyCalculusForBinary(disturbanceArrayBits.AsSpan(0, sequenceLengthInBits));
            entropySet.Add(entropy);
            ArrayPool<int>.Shared.Return(disturbanceArrayBits, true);
        }

        var entropyMin = entropySet.Min(); entrophyMinSum += entropyMin;
        reportCompiler.AppendLine($"ENTROPY MIN: {entropyMin.ToString("N3", culture.NumberFormat)}");
        var entropyMax = entropySet.Max(); entrophyMaxSum += entropyMax;
        reportCompiler.AppendLine($"ENTROPY MAX: {entropyMax.ToString("N3", culture.NumberFormat)}");
        var entropyAvg = entropySet.Average(); entrophyAvgSum += entropyAvg;
        reportCompiler.AppendLine($"ENTROPY AVG: {entropyAvg.ToString("N3", culture.NumberFormat)}");
        var entropyStdDev = Util.PopulationStandardDeviation(entropySet); entrophyStdDevSum += entropyStdDev;
        reportCompiler.AppendLine($"ENTROPY STD DEV: {entropyStdDev.ToString("N3", culture.NumberFormat)}");

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
