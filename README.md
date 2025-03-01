-- Implemented by Everton Lira (evertonlira@gmail.com)

-- Prerequisites
	- Application runs on Visual Studio 2022 (VS), freely provided here: https://visualstudio.microsoft.com/downloads/
	- Application depends on .NET SDK 8, freely provided at: https://dotnet.microsoft.com/en-us/download/dotnet/8.0

-- Setup Instructions
	Both featured algorithms, HCA and VHCA, are implemented in separate projects, 'CACrypto.HCA' and 'CACrypto.VHCA' respectively
	Each of these projects has a 'Program.cs' file that demonstrates the algorithm's basic functionality
	To run the application, simply load the 'CACrypto.sln' file in Visual Studio, and run the desired project

-- Aknowledgements
	- The HCA algorithm was implemented based on the paper:
		“A reversible system based on hybrid toggle radius-4 cellular automata and its application as a block cipher”
		by Everton R. Lira, Heverton B. de Macêdo, Danielli A. Lima, Leonardo Alt & Gina M. B. Oliveira
		Available at: https://link.springer.com/article/10.1007/s11047-023-09941-6
	- The VHCA algorithm was implemented based on the paper:
		"A Block Cipher Based on Hybrid Radius-1 Cellular Automata"
		by Everton R. Lira, Bastien Chopard, Luiz Gustavo A. Martins & Gina M. B. Oliveira
		Available at: https://www.oldcitypublishing.com/journals/jca-home/jca-issue-contents/jca-volume-18-number-2-3-2024/jca-18-2-3-p-157-186/
	- Both papers and this source code were developed as part of a Computer Science PhD at the Federal University of Uberlândia (UFU), Brazil
	- Authors are grateful for the financial support provided by the Brazilian funding agency CAPES
