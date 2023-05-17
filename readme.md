Visual Studio 2019 C++ project to create a .exe file which loads the [WriteConsoleToWriteFileWrapper64.dll](https://github.com/sp00n/WriteConsoleToWriteFileWrapperDll) (or WriteConsoleToWriteFileWrapper32.dll) DLL file to be able to hook into WriteConsoleW calls, and redirect them to WriteFile calls instead. It will also create a file with the output if a /dlllog: argument is provided to the command.

More precisely, it is used to generate a log file for [y-cruncher](http://www.numberworld.org/y-cruncher/), which it normally doesn't.


The code is a based on the ["withdll" sample from Detours 4.0.1](https://github.com/microsoft/Detours/tree/4.0.1/samples/withdll), but customized a bit (no additional DLLs, always load the default DLL instead).
[Detours](https://github.com/microsoft/Detours) 4.0.1 is required for this and is included in the /packages folder.