BEHOLD!

This is a managed (.NET) wrapper for Sipa's secp256k1 ultra-fast implementation.

Sipa's work can be found here
	https://github.com/sipa/secp256k1

Kudos also to Piotr for his work on a windows makefile
	https://github.com/piotrnar/secp256k1

And kudos to all the Piotrs of the world in general :).

---------------------------------------------------------------------

This Visual Studio project is ready to build.  

To use, you've got 2 options:
	1a) Right click your solution, add existing project, and add this project.
	1b) Right-click your project, add reference, click solution and add this.
	...or...
	2) Build this, grab the DLL, and add a reference to the DLL itself.

Note: This is a 64-bit build.  Your project must be set to 64-bit as well.

Note: This targets .NET Framework 4.5, but you can retarget to whatever you like.

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

This wrapper relies on 3 library files:
	libgcc.a (from Mingw64: http://mingw-w64.sourceforge.net/)
	libgmp.a (from gmp: http://gmplib.org/)
	libsecp256k1 (from Sipa's project)

---------------------------------------------------------------------

Build notes for secp256k1:

The configure/makefile/makefile.w64/winconfig.sh didn't work for me.  But it
gave me some hints.  I was able to build secp256k1 on my windows machine using
this procedure.  (Yasm & Mingw64 installed, assuming gmp already built)

In the secp256k1 folder, execute:
1) yasm -f win64 -o obj\field_5x64_asm.o src\field_5x64_asm.asm
2) x86_64-w64-mingw32-gcc-4.8.1.exe -I gmp -fPIC -std=gnu99 -DNDEBUG -O2 
	-DUSE_NUM_GMP -DUSE_FIELD_INV_NUM -DUSE_FIELD_5X64 -DUSE_FIELD_5X64_ASM	
	src\secp256k1.c -c -o obj\secp256k1.o 
3) x86_64-w64-mingw32-gcc-4.8.1.exe -I gmp -std=gnu99 -DUSE_NUM_GMP 
	-DUSE_FIELD_INV_NUM -DUSE_FIELD_5X64 -DUSE_FIELD_5X64_ASM -DVERIFY 
	-fstack-protector-all -O2 -ggdb3 src\tests.c obj\field_5x64_asm.o 
	-lgmp -L gmp -o tests
4) ar -rs libsecp256k1.a obj\field_5x64_asm.o obj\secp256k1.o 


