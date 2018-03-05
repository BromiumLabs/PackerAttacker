@if not defined INCLUDE (
	echo Must be run from a "Developer Command Prompt for VS"
) else (

if not exist "build" mkdir build

if exist deps\\detours\\lib.X86\\detours.lib (
    echo NOT BUILDING Detours BECAUSE detours.lib ALREADY EXISTS.
    echo To force rebuild of Detours, RUN buildclean.bat
    cd build && cmake -G %1 Win32 ..\\ && cd ..
) else (
	echo BUILDING Detours BECAUSE detours.lib DOESN'T EXIST.
    cd deps\\detours && nmake && cd ..\\..\\build && cmake -G %1 Win32 ..\\ && cd ..
)

)