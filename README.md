# Mockingjay
Tests and implementation of Mockingjay technique

The code was created for security researchers to use for exploration and tests of this techinque for their own purposes.

Original authors of techinque and further details can be found here:

[https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution]

# shellcode and code execution
Shellcode should be placed in funx32.h or funx64.h, and the key in key.h within the same folder as the c file of either mockingjay-local or mockingjay-remote.

The shellcode is expected to be simply XOR'd. This is just to prevent static AV signatures from flagging and remove the code. 

Default key is "pizza".

Default shellcode is msf's windows/exec or windows/x64/exec, CMD=calc.exe

nop.h in both mockingjay folders is simply a 2048 B nopsled. 

Both mocking-local and mockingjay-remote utilize this in order to not have to be exact on where the user shellcode lands in the RWX space. 

In my tests with mockingjay-remote, this allowed me to expand shellcode execution to the 32-bit version of ssh.exe that came packaged with my VS2019 install.

To compile, simply load into VS 2019+ and "Build Solution"

Use of this project, compiled or uncompiled code, is AS IS and carries no warranty and I am not liable for damages occured,
  as this application is provided for educational and development purposes.

USE AT YOU OWN RISK!

# Mockingjay-local
Uses a user specified DLL to load, locate RWX space, write shellcode into said space in memory, and final execute such.

Based off the first technique in the whitepaper above, but I did not implement Hell's Gate-left as an exercise for the reader :-) 

USAGE: > mockingjay-local (path to DLL)

   ex. > mockingjay-local .\VS2022-binaries\msys-2.0.dll
```
.\x64\Debug\mockingjay-local.exe .\VS2022-binaries\msys-2.0.dll
[!] Using 64-bit payload
[!] Size of key: 5
[!] Shc decrypted 277 bytes!
Section Name: /4
Virtual Size: 0x3890
Virtual Address: 0x1EC000
Size of Raw Data: 0x3A00
Characteristics: 0xE0000020
---------------------------
[!] RWX Section Addr calculated as:        21022c000
[!] Executing shellcode
```
![image](https://github.com/khr0x40sh/Mockingjay/assets/6656699/56c22858-b369-4818-aa37-2391a35c7748)


# Mockingjay-remote
Uses a user specified binary in which uses a DLL with RWX space, and a hexidecimal representation of the address of where to begin writing the shellcode in the RWX space.

Based off the second technique in the whitepaper. The example provided below should pretty reliably pop calc.

USAGE: > mockingjay-remote (path to EXE args) (addr)

   ex: > mockingjay-remote ".\VS2022-binaries\ssh.exe decoy@decoy.com" 0x21022D120

```
.\x64\Debug\mockingjay-remote.exe ".\VS2022-binaries\ssh.exe decoy@decoy.com" 0x21022D120
       21022d120
[!] msys-2.0.dll found!
[+] Proc launched with PID of: 4816
[!] Using 64-bit payload
[!] Key length detected as 5
[+] RWX space in DLL overwritten successfully!
[!] Have some cheezburgers...
```
![image](https://github.com/khr0x40sh/Mockingjay/assets/6656699/26653633-47e7-4528-8489-ead244261112)


# RWXFinder
Uses a user supplied folder path to which it will hunt for RWX space in a DLL. 

Based off this repo: [https://github.com/pwnsauc3/RWXfinder] and data from the whitepaper.

USAGE: > mrwxfinder.exe (folder path)

   ex: > rwxfinder.exe "C:\\Program Files (x86)\\"
