BEHOLD!

This is a managed (.NET) wrapper for Sipa's secp256k1 ultra-fast implementation.

Sipa's work can be found here
	https://github.com/bitcoin/secp256k1


[WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING]
[WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING]

--> This version is almost entirely untested
--> It was slapped together and posted in response to a request

[WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING]
[WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING]

---------------------------------------------------------------------

The secp256k1 implementation by Sipa was created for use primarily for bitcoin
applications.  Microsoft's cryptographic tools support secp256r1, but not the
secp256k1 curve.  Therefore, the bouncy castle library seems an attractive
choice to use in a .NET app.  

Attractive, that is, until you verify the blockchain with it.  24 hours of
100% CPU usage on my very-powerful development machine made it only to block
130000 or so.

Sipa's secp256k1 is 100-1000x faster.

---------------------------------------------------------------------

The settings for the project are by default "MachineX86 (/MACHINE:X86)". For
64 bit projects, switch it in the project properties.