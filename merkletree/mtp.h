//
//

#ifndef ZCOIN_MTP_H
#define ZCOIN_MTP_H

#endif //ZCOIN_MTP_H

#ifdef __APPLE_CC__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h> 
#endif

#include "merkle-tree.hpp"


#include <immintrin.h>
#include "argon2ref/core.h"
#include "argon2ref/argon2.h"
#include "argon2ref/thread.h"
#include "argon2ref/blake2.h"
#include "argon2ref/blake2-impl.h"
#include "argon2ref/blamka-round-opt.h"
//#include "merkletree/sha.h"

//#include "openssl\sha.h"

#include "uint256.h"
//#include "serialize.h"

#ifdef __cplusplus

void scopy_argon_blockS(argon_blockS *dst, const argon_block *src);

void mtp_hash(char* output, const char* input, unsigned int d, uint32_t TheNonce);

extern "C"
#endif
argon2_context init_argon2d_param(const char* input);



#ifdef __cplusplus
void getargon_blockindex_orig(uint32_t ij, argon2_instance_t *instance, uint32_t *out_ij_prev, uint32_t *out_computed_ref_argon_block);

void getargon_blockindex(int thr_id, cl_command_queue Queue, cl_mem block, cl_mem block2, uint32_t ij, argon2_instance_t *instance, uint32_t *out_ij_prev, uint32_t *out_computed_ref_argon_block);


//int mtp_solver_withargon_block(uint32_t TheNonce, argon2_instance_t *instance, unsigned int d, argon_block_mtpProof *output,
// uint8_t *resultMerkleRoot, MerkleTree TheTree,uint32_t* input, uint256 hashTarget);

int mtp_solver_orig(uint32_t TheNonce, argon2_instance_t *instance,
	argon_blockS *nargon_blockMTP /*[72 * 2][128]*/, unsigned char *nProofMTP, unsigned char* resultMerkleRoot, unsigned char* mtpHashValue,
	MerkleTree TheTree, uint32_t* input, uint256 hashTarget);


extern "C"
#endif
int mtp_solver(int thr_id, cl_command_queue Queue, cl_mem clblock, cl_mem clblock2, uint32_t TheNonce, argon2_instance_t *instance,
	argon_blockS *nargon_blockMTP /*[72 * 2][128]*/, unsigned char *nProofMTP, unsigned char* resultMerkleRoot, unsigned char* mtpHashValue,
	MerkleTree TheTree, uint32_t* input, uint256 hashTarget);


#ifdef __cplusplus

MerkleTree::Elements mtp_init(argon2_instance_t *instance);
MerkleTree::Elements mtp_init2(argon2_instance_t *instance);

void  mtp_init3(argon2_instance_t *instance, int thr_id, MerkleTree &ThatTree);

#endif