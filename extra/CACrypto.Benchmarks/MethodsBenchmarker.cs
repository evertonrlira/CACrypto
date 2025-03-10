using BenchmarkDotNet.Attributes;
using CACrypto.Commons;
using CACrypto.HCA;
using CACrypto.VHCA;
using System.Text;

namespace CACrypto.Benchmarks;

[MemoryDiagnoser]
public class MethodsBenchmarker
{
    private byte[] _inputBytes = null!;
    private byte[] _outputBytes = null!;
    private HCAProvider _hca = null!;
    private HCAKey _hcaKey = null!;
    private VHCAKey _vhcaKey = null!;
    private VHCAProvider _vhca = null!;

    [GlobalSetup]
    public void Setup()
    {
        _inputBytes = Encoding.ASCII.GetBytes("Avocado is a delicious and nutritive fruit.");
        _outputBytes = new byte[_inputBytes.Length];
        _hca = new HCAProvider();
        _hcaKey = (HCAKey)_hca.GenerateRandomKey();
        _vhca = new VHCAProvider();
        _vhcaKey = (VHCAKey)_vhca.GenerateRandomKey(_inputBytes.Length);
    }

    [Benchmark]
    public void EncryptUsingHCA()
    {
        _hca.EncryptAsSingleBlock(_inputBytes, _hcaKey, _outputBytes, _inputBytes.Length);
    }

    [Benchmark]
    public void DecryptUsingHCA()
    {
        _hca.DecryptAsSingleBlock(_inputBytes, _hcaKey, _outputBytes, _inputBytes.Length);
    }

    [Benchmark]
    public void GenerateSingleBlockSequenceUsingHCA()
    {
        _hca.GeneratePseudoRandomSequence(SampleSize.DefaultBlockSize);
    }

    [Benchmark]
    public void GenerateRandomSmallSequenceUsingHCA()
    {
        _hca.GeneratePseudoRandomSequence(SampleSize.SixtyFourKB);
    }

    [Benchmark]
    public void GenerateRandom1MBSequenceUsingHCA()
    {
        _hca.GeneratePseudoRandomSequence(SampleSize.OneMegaByte);
    }

    [Benchmark]
    public void EncryptUsingVHCA()
    {
        _vhca.EncryptAsSingleBlock(_inputBytes, _vhcaKey, _outputBytes, _inputBytes.Length);
    }

    [Benchmark]
    public void DecryptUsingVHCA()
    {
        _vhca.DecryptAsSingleBlock(_inputBytes, _vhcaKey, _outputBytes, _inputBytes.Length);
    }

    [Benchmark]
    public void GenerateSingleBlockSequenceUsingVHCA()
    {
        _vhca.GeneratePseudoRandomSequence(SampleSize.DefaultBlockSize);
    }

    [Benchmark]
    public void GenerateRandomSmallSequenceUsingVHCA()
    {
        _vhca.GeneratePseudoRandomSequence(SampleSize.SixtyFourKB);
    }

    [Benchmark]
    public void GenerateRandom1MBSequenceUsingVHCA()
    {
        _vhca.GeneratePseudoRandomSequence(SampleSize.OneMegaByte);
    }
}
