﻿using CACrypto.Commons;

namespace CACrypto.VHCA;

public class VHCAProvider : PermutiveCACryptoProviderBase
{
    private VHCACrypto VHCA { get; init; }

    public VHCAProvider() : base(algorithmName: VHCACrypto.Name) { VHCA = new VHCACrypto(); }

    protected override PermutiveCACryptoKey GenerateRandomKey(int blockSizeInBytes, ToggleDirection toggleDirection)
    {
        return VHCAKey.GenerateRandomKey(blockSizeInBytes, toggleDirection);
    }

    public override void EncryptAsSingleBlock(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, byte[] finalLattice, int latticeSize)
    {
        VHCACrypto.BlockEncrypt(initialLattice, mainRules, borderRules, finalLattice, latticeSize);
    }

    public override void DecryptAsSingleBlock(byte[] cipherText, Rule[] mainRules, Rule[] borderRules, byte[] plaintext, int blockSize)
    {
        VHCACrypto.BlockDecrypt(cipherText, mainRules, borderRules, plaintext, blockSize);
    }

    public override Rule[] DeriveMainRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return VHCACrypto.DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override Rule[] DeriveBorderRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return VHCACrypto.DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override int GetDefaultBlockSizeInBits()
    {
        return VHCACrypto.DefaultBlockSizeInBits;
    }

    public override int GetDefaultBlockSizeInBytes()
    {
        return VHCACrypto.DefaultBlockSizeInBytes;
    }

    protected override PermutiveCACryptoKey BuildKey(byte[] keyBytes, ToggleDirection toggleDirection)
    {
        return new VHCAKey(keyBytes, toggleDirection);
    }

    public override int GetDefaultKeySizeInBytes()
    {
        return VHCACrypto.KeySizeInBytes;
    }
}
