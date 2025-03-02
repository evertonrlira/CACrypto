namespace CACrypto.Commons;

public enum OperationMode
{
    //
    // Summary:
    //     The Cipher Block Chaining (CBC) mode introduces feedback. Before each plain text
    //     block is encrypted, it is combined with the cipher text of the previous block
    //     by a bitwise exclusive OR operation. This ensures that even if the plain text
    //     contains many identical blocks, they will each encrypt to a different cipher
    //     text block. The initialization vector is combined with the first plain text block
    //     by a bitwise exclusive OR operation before the block is encrypted. If a single
    //     bit of the cipher text block is mangled, the corresponding plain text block will
    //     also be mangled. In addition, a bit in the subsequent block, in the same position
    //     as the original mangled bit, will be mangled.
    CBC = 1,
    //
    // Summary:
    //     The Electronic Codebook (ECB) mode encrypts each block individually. Any blocks
    //     of plain text that are identical and in the same message, or that are in a different
    //     message encrypted with the same key, will be transformed into identical cipher
    //     text blocks. Important: This mode is not recommended because it opens the door
    //     for multiple security exploits. If the plain text to be encrypted contains substantial
    //     repetition, it is feasible for the cipher text to be broken one block at a time.
    //     It is also possible to use block analysis to determine the encryption key. Also,
    //     an active adversary can substitute and exchange individual blocks without detection,
    //     which allows blocks to be saved and inserted into the stream at other points
    //     without detection.
    ECB = 2,
    //
    // Summary:
    //     The Counter (CTR) mode encrypts the output of a counter, producing a 1-to-1 mapping
    //     between plain text and cipher text. The counter is incremented for each block,
    //     and the result is encrypted. CTR mode is well-suited to some modes of operation,
    //     such as random access read/write. Because there is a 1-to-1 mapping between plain
    //     text and cipher text, the cipher text can be computed in parallel. The counter
    //     value should be random and unique for each operation. The same counter value must
    //     never be used with the same key. You can combine the counter (nonce) with a message
    //     number for encryption. The initialization vector must be unique but does not need
    //     to be kept secret. The initialization vector is the same size as the block size.
    CTR = 3
}
