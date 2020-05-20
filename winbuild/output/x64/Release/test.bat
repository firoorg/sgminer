setx GPU_FORCE_64BIT_PTR 0
setx GPU_MAX_HEAP_SIZE 100
setx GPU_USE_SYNC_OBJECTS 1
setx GPU_MAX_ALLOC_PERCENT 100

setx GPU_MAX_SINGLE_ALLOC_PERCENT 100


 del *.bin

sgminer.exe --gpu-platform 2
rem --gpu-platform 2 --text-only --more-notices --verbose --debug --protocol-dump 

pause