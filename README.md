# AutoNuitkaDecompiler
- Get malware payload without dynamic analysis with this auto decompiler

- git clone https://github.com/HydraDragonAntivirus/HydraDragonAntivirus.git
- pip install -r requirements.txt
- python autonuitkadecompilerold.py
- If you want improve the project you can do by filtering process even better by detecting common text files with signatures. Currently there no signature so it can detect basic Nuitka decompiled files but if it's complex you need this signatures.
- After you get nuitkasourcecode paste to AI source code. It's filtered Nuitka bytecode code (not actual python bytecode it's special Nuitka bytecode, you can see from general extracted biggest .bin file (generally 10_3_0.bin))
- python.exe (first upython.exe) is the actual part of starting source code.