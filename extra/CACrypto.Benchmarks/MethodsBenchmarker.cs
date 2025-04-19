using BenchmarkDotNet.Attributes;
using CACrypto.Commons;
using CACrypto.HCA;
using CACrypto.VHCA;
using System.Text;

namespace CACrypto.Benchmarks;

[MemoryDiagnoser]
public class MethodsBenchmarker
{
    private byte[] _inputBlockBytes = null!;
    private byte[] _outputBlockBytes = null!;
    private byte[] _inputTextBytes = null!;
    private byte[] _outputTextBytes = null!;
    private AESProvider _aes = null!;
    private CryptoKey _aesKey = null!;
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
        var defaultBlockSizeInBytes = 16;
        _inputBlockBytes = new byte[defaultBlockSizeInBytes];
        _outputBlockBytes = new byte[defaultBlockSizeInBytes];
        Util.FillArrayWithRandomData(_inputBlockBytes);
        _inputTextBytes = Encoding.ASCII.GetBytes("Avocado is a delicious and nutritive fruit.");
        _outputTextBytes = new byte[_inputTextBytes.Length];
        _aes = new AESProvider();
        _aesKey = _aes.GenerateRandomKey();
        _hca = new HCAProvider();
        var hcaKeyForInputText = (HCAKey)_hca.GenerateRandomKey();
        _hcaMainRulesForInputText = _hca.DeriveMainRulesFromKey(hcaKeyForInputText);
        _hcaBorderRulesForInputText = _hca.DeriveMainRulesFromKey(hcaKeyForInputText);
        _hcaMainRulesForDefaultBlockSize = _hcaMainRulesForInputText;
        _hcaBorderRulesForDefaultBlockSize = _hcaBorderRulesForInputText;
        _vhca = new VHCAProvider();
        var vhcaKeyForInputText = (VHCAKey)_vhca.GenerateRandomKey(_inputTextBytes.Length);
        _vhcaMainRulesForInputText = _vhca.DeriveMainRulesFromKey(vhcaKeyForInputText);
        _vhcaBorderRulesForInputText = _vhca.DeriveMainRulesFromKey(vhcaKeyForInputText);
        var vhcaKeyForDefaultBlockSize = (VHCAKey)_vhca.GenerateRandomKey(defaultBlockSizeInBytes);
        _vhcaMainRulesForDefaultBlockSize = _vhca.DeriveMainRulesFromKey(vhcaKeyForDefaultBlockSize);
        _vhcaBorderRulesForDefaultBlockSize = _vhca.DeriveMainRulesFromKey(vhcaKeyForDefaultBlockSize);
    }

    [Benchmark]
    public void GenerateSingleBlockSequenceUsingAES()
    {
        _aes.GeneratePseudoRandomSequence(SampleSize.DefaultBlockSize);
    }

    [Benchmark]
    public void Generate1MBSequenceUsingAES()
    {
        _aes.GeneratePseudoRandomSequence(SampleSize.DefaultBlockSize);
    }

    [Benchmark]
    public void EncryptBlockUsingAES()
    {
        _aes.EncryptAsSingleBlock(_inputBlockBytes, _aesKey, _outputBlockBytes, _inputBlockBytes.Length);
    }

    [Benchmark]
    public void DecryptBlockUsingAES()
    {
        _aes.DecryptAsSingleBlock(_inputBlockBytes, _aesKey, _outputBlockBytes, _inputBlockBytes.Length);
    }

    [Benchmark]
    public void Generate1MBSequenceUsingAES()
    {
        _aes.GeneratePseudoRandomSequence(SampleSize.OneMegaByte);
    }

    [Benchmark]
    public void EncryptBlockUsingHCA()
    {
        _hca.EncryptAsSingleBlock(_inputBlockBytes, _hcaMainRulesForDefaultBlockSize, _hcaBorderRulesForDefaultBlockSize, _outputBlockBytes, _inputBlockBytes.Length);
    }

    [Benchmark]
    public void DecryptBlockUsingHCA()
    {
        _hca.DecryptAsSingleBlock(_inputBlockBytes, _hcaMainRulesForDefaultBlockSize, _hcaBorderRulesForDefaultBlockSize, _outputBlockBytes, _inputBlockBytes.Length);
    }

    [Benchmark]
    public void EncryptTextUsingHCA()
    {
        _hca.EncryptAsSingleBlock(_inputTextBytes, _hcaMainRulesForInputText, _hcaBorderRulesForInputText, _outputBytes, _inputBytes.Length);
    }

    [Benchmark]
    public void DecryptTextUsingHCA()
    {
        _hca.DecryptAsSingleBlock(_inputTextBytes, _hcaMainRulesForInputText, _hcaBorderRulesForInputText, _outputBytes, _inputBytes.Length);
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
    public void EncryptBlockUsingVHCA()
    {
        _vhca.EncryptAsSingleBlock(_inputBlockBytes, _vhcaMainRulesForInputText, _vhcaBorderRulesForInputText, _outputBlockBytes, _inputBlockBytes.Length);
    }

    [Benchmark]
    public void DecryptBlockUsingVHCA()
    {
        _vhca.DecryptAsSingleBlock(_inputBlockBytes, _vhcaMainRulesForInputText, _vhcaBorderRulesForInputText, _outputBlockBytes, _inputBlockBytes.Length);
    }

    [Benchmark]
    public void EncryptTextUsingVHCA()
    {
        _vhca.EncryptAsSingleBlock(_inputTextBytes, _vhcaMainRulesForInputText, _vhcaBorderRulesForInputText, _outputTextBytes, _inputTextBytes.Length);
    }

    [Benchmark]
    public void DecryptTextUsingVHCA()
    {
        _vhca.DecryptAsSingleBlock(_inputTextBytes, _vhcaMainRulesForInputText, _vhcaBorderRulesForInputText, _outputTextBytes, _inputTextBytes.Length);
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
        _vhca.GeneratePseudoRandomSequence(SampleSize.OneKiloByte, _vhcaMainRulesForDefaultBlockSize, _vhcaBorderRulesForDefaultBlockSize);
    }
}
