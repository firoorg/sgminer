setx GPU_FORCE_64BIT_PTR 0


setx GPU_MAX_HEAP_SIZE 100


setx GPU_USE_SYNC_OBJECTS 1


setx GPU_MAX_ALLOC_PERCENT 100


del *.bin



kernel\sgminer.exe --no-submit-stale --kernel Lyra2h  -o stratum+tcp://hpp.jkpool.com:3003 -u djm34.1 -p password -w 16 -I 16

pause