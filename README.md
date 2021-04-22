# haze
 haze binary fuzzer

 This is a fuzzer for Windows based on TinyInst
 Current version is a modification of litecov to perform fuzzing

 Fuzzer currently sorts input dir by smalles size and for each input if new coverage is found, it is added to the working queue
 Queue contents can be added to dynamically


Checkout 
```
git clone --recurse-submodules https://github.com/richinseattle/haze
```

Update
```
git pull --recurse-submodules
```

Build
```
mkdir build
cd build
cmake -G"Visual Studio 16 2019" -A x64 ..
cmake --build . --config Release
```

Usage
```
haze.exe [options] -- [target cmdline] 

Options:
    -i <input dir> 
    -o <output dir>
    -iterations <count>                 Loop iterations per input 
    -persist                            Enable hook persistence
    -loop                               Enable loop
    -target_module <module name>        Target module for loop entry point
    -target_method <method name>        Function name for loop entry point
    -nargs <count>                      Number of arguments taken by target_method
    -instrument_module <module name>    Instrument module for coverage collection     
```



Example output
```
R:\>c:\code\haze\out\build\x64-Release\haze.exe -i c:\code\fuzzdata\samples\ico -o ico -iterations 1000 -persist -target_module faster_gdiplus.exe -target_method fuzzit -nargs 1 -loop -instrument_module WindowsCodecs.dll -- c:\winafl\bin64\faster_gdiplus.exe @@
Haze Binary Fuzzer

Selecting inputs for queue..
[+] c:\code\fuzzdata\samples\ico\256-height.ico
[-] c:\code\fuzzdata\samples\ico\256-width.ico
[+] c:\code\fuzzdata\samples\ico\favicon.ico
[+] c:\code\fuzzdata\samples\ico\ico_bmp_height.ico
[+] c:\code\fuzzdata\samples\ico\bmp_with_alpha.ico
[+] c:\code\fuzzdata\samples\ico\vista-png-compressed.ico
[+] c:\code\fuzzdata\samples\ico\favicon-optimal.ico
[-] c:\code\fuzzdata\samples\ico\vista-1-ico-3-png.ico
[+] c:\code\fuzzdata\samples\ico\favicon2.ico

7 of 9 inputs added to queue
random seed: 1601523484
Mutating [6/7] for 1000 iterations: 7-favicon2.ico
    NEWCOV ### Iteration      4: Found 4 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration     23: Found 1 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration     70: Found 1 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration    128: Found 12 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration    136: Found 2 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration    227: Found 4 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration    331: Found 1 new offsets in WindowsCodecs.dll
1000 iterations complete. Time elapsed: 6176ms  average exec/s: 161.917

Mutating [0/14] for 1000 iterations: 1-256-height.ico
    NEWCOV ### Iteration     10: Found 3 new offsets in WindowsCodecs.dll
1000 iterations complete. Time elapsed: 4193ms  average exec/s: 238.493

Mutating [5/15] for 1000 iterations: 6-favicon-optimal.ico
    NEWCOV ### Iteration     10: Found 1 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration     23: Found 2 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration     59: Found 3 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration     80: Found 6 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration     91: Found 15 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration    140: Found 1 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration    282: Found 9 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration    377: Found 2 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration    646: Found 1 new offsets in WindowsCodecs.dll
1000 iterations complete. Time elapsed: 6542ms  average exec/s: 152.858

Mutating [7/24] for 1000 iterations: 05-7-favicon2.ico
    NEWCOV ### Iteration    844: Found 21 new offsets in WindowsCodecs.dll
    NEWCOV ### Iteration    959: Found 1 new offsets in WindowsCodecs.dll
1000 iterations complete. Time elapsed: 6133ms  average exec/s: 163.052
```