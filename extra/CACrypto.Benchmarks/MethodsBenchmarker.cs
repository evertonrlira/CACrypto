using BenchmarkDotNet.Attributes;
using CACrypto.Commons;
using CACrypto.HCA;
using CACrypto.VHCA;
using System.Text;

namespace CACrypto.Benchmarks;

[MemoryDiagnoser]
public class MethodsBenchmarker
{
    private byte[] _plaintextBytes = null!;
    private HCAProvider _hca = null!;
    private HCAKey _hcaKey = null!;
    private VHCAKey _vhcaKey = null!;
    private VHCAProvider _vhca = null!;

    [GlobalSetup]
    public void Setup()
    {
        _plaintextBytes = Encoding.ASCII.GetBytes("Avocado is a delicious and nutritive fruit.");
        _hca = new HCAProvider();
        _hcaKey = (HCAKey)_hca.GenerateRandomKey();
        _vhca = new VHCAProvider();
        _vhcaKey = (VHCAKey)_vhca.GenerateRandomKey();
    }

    [Benchmark]
    public byte[] EncryptUsingHCA()
    {
        return _hca.EncryptAsSingleBlock(_plaintextBytes, _hcaKey);
    }

    [Benchmark]
    public byte[] GenerateRandom1MBSequenceUsingHCA()
    {        
        return _hca.GeneratePseudoRandomSequence(SampleSize.OneMegaByte);
    }

    [Benchmark]
    public byte[] EncryptUsingVHCA()
    {
        return _vhca.EncryptAsSingleBlock(_plaintextBytes, _vhcaKey);
    }

    [Benchmark]
    public byte[] GenerateRandom1MBSequenceUsingVHCA()
    {
        return _vhca.GeneratePseudoRandomSequence(SampleSize.OneMegaByte);
    }
}