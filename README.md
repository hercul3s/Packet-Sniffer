# Packet Logger / Decryptor via Windivert

## Description
It decompresses & decrypts the data received from the Network Layer 
without any injection and optionally prints them to a .Txt file or console.

## How to use

1. Move the Windivert.dll and sys file to the same directory as the executable.
2. [Launch] the `PacketSniffer.exe`
3. [Launch] the `MMORPG.exe`

## How to build from source
1. Clone or download the repository
2. Download the latest version WinDivert [here](https://github.com/basil00/Divert/releases/tag/v2.2.0)
3. Open the solution with Visual Studio 2019 or above
4. Switch the build configuration to Debug or Release
5. Build the solution.

## Screenshot
![](screenshots/ss.gif)

## ---------------
- [WinDivert](https://reqrypt.org/windivert.html)
- [Rijndael](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Layer-3](https://en.wikipedia.org/wiki/Network_layer)
