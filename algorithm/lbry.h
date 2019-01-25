#ifndef LBRY_H
#define LBRY_H

#include "miner.h"

extern void lbry_regenhash(struct work *work);
extern void precalc_hash_sha256(dev_blk_ctx *blk, uint32_t *state, uint32_t *pdata);
#endif
