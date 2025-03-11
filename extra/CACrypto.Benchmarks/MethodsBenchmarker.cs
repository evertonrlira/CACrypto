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
    private Rule[] _hcaMainRulesForInputText = null!;
    private Rule[] _hcaBorderRulesForInputText = null!;
    private Rule[] _hcaMainRulesForDefaultBlockSize = null!;
    private Rule[] _hcaBorderRulesForDefaultBlockSize = null!;
    private Rule[] _vhcaMainRulesForInputText = null!;
    private Rule[] _vhcaBorderRulesForInputText = null!;
    private Rule[] _vhcaMainRulesForDefaultBlockSize = null!;
    private Rule[] _vhcaBorderRulesForDefaultBlockSize = null!;
    private VHCAProvider _vhca = null!;

    [GlobalSetup]
    public void Setup()
    {
        _inputBytes = Encoding.ASCII.GetBytes("Avocado is a delicious and nutritive fruit.");
        _outputBytes = new byte[_inputBytes.Length];
        _hca = new HCAProvider();
        var hcaKeyForInputText = (HCAKey)_hca.GenerateRandomKey();
        _hcaMainRulesForInputText = _hca.DeriveMainRulesFromKey(hcaKeyForInputText);
        _hcaBorderRulesForInputText = _hca.DeriveMainRulesFromKey(hcaKeyForInputText);
        _hcaMainRulesForDefaultBlockSize = _hcaMainRulesForInputText;
        _hcaBorderRulesForDefaultBlockSize = _hcaBorderRulesForInputText;
        _vhca = new VHCAProvider();
        var vhcaKeyForInputText = (VHCAKey)_vhca.GenerateRandomKey(_inputBytes.Length);
        _vhcaMainRulesForInputText = _vhca.DeriveMainRulesFromKey(vhcaKeyForInputText);
        _vhcaBorderRulesForInputText = _vhca.DeriveMainRulesFromKey(vhcaKeyForInputText);
        var vhcaKeyForDefaultBlockSize = (VHCAKey)_vhca.GenerateRandomKey(_vhca.GetDefaultBlockSizeInBytes());
        _vhcaMainRulesForDefaultBlockSize = _vhca.DeriveMainRulesFromKey(vhcaKeyForDefaultBlockSize);
        _vhcaBorderRulesForDefaultBlockSize = _vhca.DeriveMainRulesFromKey(vhcaKeyForDefaultBlockSize);
    }

    [Benchmark]
    public void EncryptUsingHCA()
    {
        _hca.EncryptAsSingleBlock(_inputBytes, _hcaMainRulesForInputText, _hcaBorderRulesForInputText, _outputBytes, _inputBytes.Length);
    }

    [Benchmark]
    public void DecryptUsingHCA()
    {
        _hca.DecryptAsSingleBlock(_inputBytes, _hcaMainRulesForInputText, _hcaBorderRulesForInputText, _outputBytes, _inputBytes.Length);
    }

    [Benchmark]
    public void GenerateSingleBlockSequenceUsingHCA()
    {
        _hca.GeneratePseudoRandomSequence(SampleSize.DefaultBlockSize, _hcaMainRulesForDefaultBlockSize, _hcaBorderRulesForDefaultBlockSize);
    }

    [Benchmark]
    public void GenerateSmallSequenceUsingHCA()
    {
        _hca.GeneratePseudoRandomSequence(SampleSize.SixtyFourKB, _hcaMainRulesForDefaultBlockSize, _hcaBorderRulesForDefaultBlockSize);
    }

    [Benchmark]
    public void Generate1MBSequenceUsingHCA()
    {
        _hca.GeneratePseudoRandomSequence(SampleSize.OneMegaByte, _hcaMainRulesForDefaultBlockSize, _hcaBorderRulesForDefaultBlockSize);
    }

    [Benchmark]
    public void EncryptUsingVHCA()
    {
        _vhca.EncryptAsSingleBlock(_inputBytes, _vhcaMainRulesForInputText, _vhcaBorderRulesForInputText, _outputBytes, _inputBytes.Length);
    }

    [Benchmark]
    public void DecryptUsingVHCA()
    {
        _vhca.DecryptAsSingleBlock(_inputBytes, _vhcaMainRulesForInputText, _vhcaBorderRulesForInputText, _outputBytes, _inputBytes.Length);
    }

    [Benchmark]
    public void GenerateSingleBlockSequenceUsingVHCA()
    {
        _vhca.GeneratePseudoRandomSequence(SampleSize.DefaultBlockSize, _vhcaMainRulesForDefaultBlockSize, _vhcaBorderRulesForDefaultBlockSize);
    }

    [Benchmark]
    public void GenerateSmallSequenceUsingVHCA()
    {
        _vhca.GeneratePseudoRandomSequence(SampleSize.SixtyFourKB, _vhcaMainRulesForDefaultBlockSize, _vhcaBorderRulesForDefaultBlockSize);
    }

    [Benchmark]
    public void Generate1MBSequenceUsingVHCA()
    {
        _vhca.GeneratePseudoRandomSequence(SampleSize.OneMegaByte, _vhcaMainRulesForDefaultBlockSize, _vhcaBorderRulesForDefaultBlockSize);
    }
}
