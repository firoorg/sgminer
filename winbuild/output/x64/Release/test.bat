setx GPU_FORCE_64BIT_PTR 0
setx GPU_MAX_HEAP_SIZE 100
setx GPU_USE_SYNC_OBJECTS 1
setx GPU_MAX_ALLOC_PERCENT 100

setx GPU_MAX_SINGLE_ALLOC_PERCENT 100


del *.bin

rem sgminer.exe --kernel mtp_nvidia   -o stratum+tcp://zcoin.mintpond.com:3000  -u  aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak.worker -p 0,strict,verbose,d=700 --worksize 256 --intensity 18 --text-only --more-notices --verbose --debug --protocol-dump --device 1

sgminer.exe --kernel mtp  -o stratum+tcp://zcoin.mintpond.com:3000  -u  aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak.worker -p 0,strict,verbose,d=700 --intensity 20  --device 0,1 --worksize 64

pause