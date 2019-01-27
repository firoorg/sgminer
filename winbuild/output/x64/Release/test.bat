setx GPU_FORCE_64BIT_PTR 0
setx GPU_MAX_HEAP_SIZE 100
setx GPU_USE_SYNC_OBJECTS 1
setx GPU_MAX_ALLOC_PERCENT 100

setx GPU_MAX_SINGLE_ALLOC_PERCENT 100


del *.bin

sgminer.exe --kernel mtp_vega  -o stratum+tcp://zcoin.mintpond.com:3000  -u  aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak.worker -p 0,strict,verbose,d=700  --intensity 18 --text-only --more-notices --verbose --debug --protocol-dump --device 1

rem sgminer.exe --kernel mtp_vega  -o stratum+tcp://zcoin.mintpond.com:3000  -u  aDn7MMYjVQqenT11VFDYHfFdwXmSTRUTak.worker -p 0,strict,verbose,sd=700 --intensity 20  --device 0,1


pause