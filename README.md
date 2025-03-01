### Description
 - This solution contains simple implementations for two cryptographic methods, **HCA** and **VHCA**. Both are block ciphers for private key cryptography that are based on Cellular Automata. Cellular Automata (CA) is a time-discrete computational model that features inherent parallelism that can be harnessed using appropriate hardware. The x86-64 implementations contained here do not harness said potential, but are useful to validate the methods' cryptographic robustness.

### Prerequisites
 - Application runs on Visual Studio 2022 (VS), freely provided here: https://visualstudio.microsoft.com/downloads/
 - Application depends on .NET SDK 8, freely provided at: https://dotnet.microsoft.com/en-us/download/dotnet/8.0

### Setup Instructions
 - Both featured algorithms, **HCA** and **VHCA**, are implemented in separate projects, 'CACrypto.HCA' and 'CACrypto.VHCA' respectively
 - Each of these projects has a 'Program.cs' file that demonstrates the algorithm's basic functionality
 - To run the application, simply load the 'CACrypto.sln' file in Visual Studio, and run the desired project

### Aknowledgements
 - The **HCA** algorithm was implemented based on the paper:
	- Title: “A reversible system based on hybrid toggle radius-4 cellular automata and its application as a block cipher”
	- Authors: Everton R. Lira, Heverton B. de Macêdo, Danielli A. Lima, Leonardo Alt & Gina M. B. Oliveira
	- Available [Here](https://link.springer.com/article/10.1007/s11047-023-09941-6)
 - The **VHCA** algorithm was implemented based on the paper:
	 - Title: "A Block Cipher Based on Hybrid Radius-1 Cellular Automata"
	 - Authors: Everton R. Lira, Bastien Chopard, Luiz Gustavo A. Martins & Gina M. B. Oliveira
	 - Available [Here](https://www.oldcitypublishing.com/journals/jca-home/jca-issue-contents/jca-volume-18-number-2-3-2024/jca-18-2-3-p-157-186/)
- Both papers and this source code were developed as part of a Computer Science PhD at the Federal University of Uberlândia (UFU), Brazil
- Authors are grateful for the financial support provided by the Brazilian funding agency CAPES

### Implemented by Everton Lira (evertonlira@gmail.com)
