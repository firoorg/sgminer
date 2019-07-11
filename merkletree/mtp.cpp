//
//
//#pragma once 
#include "mtp.h"

#ifdef _MSC_VER
#include <windows.h>
#include <winbase.h> /* For SecureZeroMemory */
#endif

#include <ios>
#include <stdio.h>
#include <iostream>
#if defined __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "../algorithm.h"

#define memcost 4*1024*1024
static const unsigned int d_mtp = 1;
static const uint8_t L = 64;
static const unsigned int memory_cost = memcost;

//extern void get_argon_block(int thr_id, void* d, uint32_t index){};
//extern void get_argon_block(int thr_id, void* clblock, uint32_t index);

//extern void get_argon_block(cl_command_queue Queue,cl_mem block, cl_mem block2, uint8_t* clblock,  uint32_t index);

void get_argon_block(cl_command_queue Queue, cl_mem block, cl_mem block2, uint8_t* clblock, uint32_t index)
{
	size_t TheSize = 128 * sizeof(uint64_t);
	size_t TheOffSet = 128 * sizeof(uint64_t)*index;
	size_t Shift = 2 * 1024 * 1024 * 128 * sizeof(uint64_t);
	cl_int status;
	if (index < 2 * 1024 * 1024)
		status = clEnqueueReadBuffer(Queue, block, CL_TRUE, TheOffSet, TheSize, clblock, 0, NULL, NULL);
	else
		status = clEnqueueReadBuffer(Queue, block2, CL_TRUE, TheOffSet - Shift, TheSize, clblock, 0, NULL, NULL);

}

void get_argon_block_old(cl_command_queue Queue, cl_mem block, cl_mem block2, uint8_t* clblock, uint32_t index)
{
	size_t TheSize = 16 * sizeof(uint64_t);
	size_t TheOffSet = 16 * sizeof(uint64_t)*index;
	size_t Shift = 2 * 1024 * 1024 * 128 * sizeof(uint64_t);
	cl_int status;

	for (int i=0;i<4;i++) {
		uint8_t * blocksifter = &clblock[i * 16 * 8];
		size_t TheNewOff = TheOffSet + i * (4 * 1024 * 1024) * 16 * 8;
		status = clEnqueueReadBuffer(Queue, block, CL_TRUE, TheNewOff, TheSize, blocksifter, 0, NULL, NULL);
	}

	for (int i = 0; i<4; i++) {
		uint8_t * blocksifter = &clblock[(i+4) * 16 * 8];
		size_t TheNewOff = TheOffSet + i * (4 * 1024 * 1024) * 16 * 8;
		status = clEnqueueReadBuffer(Queue, block2, CL_TRUE, TheNewOff, TheSize, blocksifter, 0, NULL, NULL);
	}

}

void get_argon_block_short(cl_command_queue Queue, cl_mem block, uint8_t* clblock, uint32_t index)
{
	size_t TheSize = 128 * sizeof(uint64_t);
	size_t TheOffSet = 128 * sizeof(uint64_t)*index;
	size_t Shift = 2 * 1024 * 1024 * 128 * sizeof(uint64_t);
	cl_int status;
		status = clEnqueueReadBuffer(Queue, block, CL_TRUE, TheOffSet, TheSize, clblock, 0, NULL, NULL);


}


uint32_t index_beta(const argon2_instance_t *instance,
	const argon2_position_t *position, uint32_t pseudo_rand,
	int same_lane) {
	
	uint32_t reference_area_size;
	uint64_t relative_position;
	uint32_t start_position, absolute_position;

	if (0 == position->pass) {
		/* First pass */
		if (0 == position->slice) {
			/* First slice */
			reference_area_size =
				position->index - 1; /* all but the previous */
		}
		else {
			if (same_lane) {
				/* The same lane => add current segment */
				reference_area_size =
					position->slice * instance->segment_length +
					position->index - 1;
			}
			else {
				reference_area_size =
					position->slice * instance->segment_length +
					((position->index == 0) ? (-1) : 0);
			}
		}
	}
	else {
		/* Second pass */
		if (same_lane) {
			reference_area_size = instance->lane_length -
				instance->segment_length + position->index -
				1;
		}
		else {
			reference_area_size = instance->lane_length -
				instance->segment_length +
				((position->index == 0) ? (-1) : 0);
		}
	}

	/* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
	* relative position */
	relative_position = pseudo_rand;
	relative_position = relative_position * relative_position >> 32;
	relative_position = reference_area_size - 1 -
		(reference_area_size * relative_position >> 32);

	/* 1.2.5 Computing starting position */
	start_position = 0;

	if (0 != position->pass) {
		start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
			? 0
			: (position->slice + 1) * instance->segment_length;
	}

	/* 1.2.6. Computing absolute position */
	absolute_position = (start_position + relative_position) %
		instance->lane_length; /* absolute position */
	return absolute_position;
}



void getargon_blockindex_orig(uint32_t ij, argon2_instance_t *instance, uint32_t *out_ij_prev, uint32_t *out_computed_ref_argon_block)
{
	uint32_t ij_prev = 0;
	if (ij%instance->lane_length == 0)
		ij_prev = ij + instance->lane_length - 1;
	else
		ij_prev = ij - 1;

	if (ij % instance->lane_length == 1)
		ij_prev = ij - 1;

	uint64_t prev_argon_block_opening = instance->memory[ij_prev].v[0];
	uint32_t ref_lane = (uint32_t)((prev_argon_block_opening >> 32) % instance->lanes);

	uint32_t pseudo_rand = (uint32_t)(prev_argon_block_opening & 0xFFFFFFFF);

	uint32_t Lane = ((ij) / instance->lane_length);
	uint32_t Slice = (ij - (Lane * instance->lane_length)) / instance->segment_length;
	uint32_t posIndex = ij - Lane * instance->lane_length - Slice * instance->segment_length;


	uint32_t rec_ij = Slice*instance->segment_length + Lane *instance->lane_length + (ij % instance->segment_length);

	if (Slice == 0)
		ref_lane = Lane;


	argon2_position_t position = { 0, Lane , (uint8_t)Slice, posIndex };

	uint32_t ref_index = index_beta(instance, &position, pseudo_rand, ref_lane == position.lane);

	uint32_t computed_ref_argon_block = instance->lane_length * ref_lane + ref_index;

	*out_ij_prev = ij_prev;
	*out_computed_ref_argon_block = computed_ref_argon_block;
}


void getargon_blockindex(int thr_id, cl_command_queue Queue, cl_mem block, cl_mem block2, uint32_t ij, argon2_instance_t *instance, uint32_t *out_ij_prev, uint32_t *out_computed_ref_argon_block)
{
	uint32_t ij_prev = 0;
	if (ij%instance->lane_length == 0)
		ij_prev = ij + instance->lane_length - 1;
	else
		ij_prev = ij - 1;

	if (ij % instance->lane_length == 1)
		ij_prev = ij - 1;

	argon_block b;
	get_argon_block(/*thr_id,*/Queue,block, block2, (uint8_t*)&b.v, ij_prev);
	uint64_t prev_argon_block_opening = b.v[0];//instance->memory[ij_prev].v[0];
	uint32_t ref_lane = (uint32_t)((prev_argon_block_opening >> 32) % instance->lanes);

	uint32_t pseudo_rand = (uint32_t)(prev_argon_block_opening & 0xFFFFFFFF);

	uint32_t Lane = ((ij) / instance->lane_length);
	uint32_t Slice = (ij - (Lane * instance->lane_length)) / instance->segment_length;
	uint32_t posIndex = ij - Lane * instance->lane_length - Slice * instance->segment_length;


	uint32_t rec_ij = Slice*instance->segment_length + Lane *instance->lane_length + (ij % instance->segment_length);

	if (Slice == 0)
		ref_lane = Lane;


	argon2_position_t position = { 0, Lane , (uint8_t)Slice, posIndex };

	uint32_t ref_index = index_beta(instance, &position, pseudo_rand, ref_lane == position.lane);

	uint32_t computed_ref_argon_block = instance->lane_length * ref_lane + ref_index;

	*out_ij_prev = ij_prev;
	*out_computed_ref_argon_block = computed_ref_argon_block;
}


void getargon_blockindex_short(int thr_id, cl_command_queue Queue, cl_mem block, uint32_t ij, argon2_instance_t *instance, uint32_t *out_ij_prev, uint32_t *out_computed_ref_argon_block)
{
	uint32_t ij_prev = 0;
	if (ij%instance->lane_length == 0)
		ij_prev = ij + instance->lane_length - 1;
	else
		ij_prev = ij - 1;

	if (ij % instance->lane_length == 1)
		ij_prev = ij - 1;

	argon_block b;
	get_argon_block_short(/*thr_id,*/Queue, block, (uint8_t*)&b.v, ij_prev);
	uint64_t prev_argon_block_opening = b.v[0];//instance->memory[ij_prev].v[0];
	uint32_t ref_lane = (uint32_t)((prev_argon_block_opening >> 32) % instance->lanes);

	uint32_t pseudo_rand = (uint32_t)(prev_argon_block_opening & 0xFFFFFFFF);

	uint32_t Lane = ((ij) / instance->lane_length);
	uint32_t Slice = (ij - (Lane * instance->lane_length)) / instance->segment_length;
	uint32_t posIndex = ij - Lane * instance->lane_length - Slice * instance->segment_length;


	uint32_t rec_ij = Slice*instance->segment_length + Lane *instance->lane_length + (ij % instance->segment_length);

	if (Slice == 0)
		ref_lane = Lane;


	argon2_position_t position = { 0, Lane , (uint8_t)Slice, posIndex };

	uint32_t ref_index = index_beta(instance, &position, pseudo_rand, ref_lane == position.lane);

	uint32_t computed_ref_argon_block = instance->lane_length * ref_lane + ref_index;

	*out_ij_prev = ij_prev;
	*out_computed_ref_argon_block = computed_ref_argon_block;
}



void Storeargon_block(void *output, const argon_block *src)
{
	for (unsigned i = 0; i < ARGON2_QWORDS_IN_argon_block; ++i) {
		store64(static_cast<uint8_t*>(output)
			+ (i * sizeof(src->v[i])), src->v[i]);
	}
}


void compute_blake2b(const argon_block& input,
	uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B])
{
	ablake2b_state state;
	ablake2b_init(&state, MERKLE_TREE_ELEMENT_SIZE_B);
	ablake2b4rounds_update(&state, input.v, ARGON2_argon_block_SIZE);
	ablake2b4rounds_final(&state, digest, MERKLE_TREE_ELEMENT_SIZE_B);
}


unsigned int trailing_zeros(char str[64]) {


    unsigned int i, d;
    d = 0;
    for (i = 63; i > 0; i--) {
        if (str[i] == '0') {
            d++;
        }
        else {
            break;
        }
    }
    return d;
}


unsigned int trailing_zeros_little_endian(char str[64]) {
	unsigned int i, d;
	d = 0;
	for (i = 0; i < 64; i++) {
		if (str[i] == '0') {
			d++;
		}
		else {
			break;
		}
	}
	return d;
}

unsigned int trailing_zeros_little_endian_uint256(uint256 hash) {
	unsigned int i, d;
	std::string temp = hash.GetHex();
	d = 0;
	for (i = 0; i < temp.size(); i++) {
		if (temp[i] == '0') {
			d++;
		}
		else {
			break;
		}
	}
	return d;
}


static void sstore_argon_block(void *output, const argon_block *src) {
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_argon_block; ++i) {
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}


void fill_argon_block(__m128i *state, const argon_block *ref_argon_block, argon_block *next_argon_block, int with_xor) {
    __m128i argon_block_XY[ARGON2_OWORDS_IN_argon_block];
    unsigned int i;

    if (with_xor) {
        for (i = 0; i < ARGON2_OWORDS_IN_argon_block; i++) {
            state[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)ref_argon_block->v + i));
            argon_block_XY[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)next_argon_block->v + i));
        }
    }
    else {
        for (i = 0; i < ARGON2_OWORDS_IN_argon_block; i++) {
            argon_block_XY[i] = state[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)ref_argon_block->v + i));
        }
    }

    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                     state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                     state[8 * i + 6], state[8 * i + 7]);
    }

    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                     state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                     state[8 * 6 + i], state[8 * 7 + i]);
    }

    for (i = 0; i < ARGON2_OWORDS_IN_argon_block; i++) {
        state[i] = _mm_xor_si128(state[i], argon_block_XY[i]);
        _mm_storeu_si128((__m128i *)next_argon_block->v + i, state[i]);
    }
}

void fill_argon_block2(__m128i *state, const argon_block *ref_argon_block, argon_block *next_argon_block, int with_xor, uint32_t argon_block_header[4]) {
	__m128i argon_block_XY[ARGON2_OWORDS_IN_argon_block];
	unsigned int i;

	if (with_xor) {
		for (i = 0; i < ARGON2_OWORDS_IN_argon_block; i++) {
			state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_argon_block->v + i));
			argon_block_XY[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)next_argon_block->v + i));
		}
	}
	else {
		for (i = 0; i < ARGON2_OWORDS_IN_argon_block; i++) {
			argon_block_XY[i] = state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_argon_block->v + i));
		}
	}

	memcpy(&state[8], argon_block_header, sizeof(__m128i));

	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
			state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
			state[8 * i + 6], state[8 * i + 7]);
	}

	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
			state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
			state[8 * 6 + i], state[8 * 7 + i]);
	}

	for (i = 0; i < ARGON2_OWORDS_IN_argon_block; i++) {
		state[i] = _mm_xor_si128(state[i], argon_block_XY[i]);
		_mm_storeu_si128((__m128i *)next_argon_block->v + i, state[i]);
	}
}

void fill_argon_block2_withIndex(__m128i *state, const argon_block *ref_argon_block, argon_block *next_argon_block, int with_xor, uint32_t argon_block_header[8], uint64_t argon_blockIndex) {
	__m128i argon_block_XY[ARGON2_OWORDS_IN_argon_block];
	unsigned int i;
    uint64_t TheIndex[2]={0,argon_blockIndex};
	if (with_xor) {
		for (i = 0; i < ARGON2_OWORDS_IN_argon_block; i++) {
			state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_argon_block->v + i));
			argon_block_XY[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)next_argon_block->v + i));
		}
	}
	else {
		for (i = 0; i < ARGON2_OWORDS_IN_argon_block; i++) {
			argon_block_XY[i] = state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_argon_block->v + i));
		}
	}
	memcpy(&state[7], TheIndex, sizeof(__m128i));
	memcpy(&state[8], argon_block_header, sizeof(__m128i));
	memcpy(&state[9], argon_block_header + 4, sizeof(__m128i));
	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
			state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
			state[8 * i + 6], state[8 * i + 7]);
	}

	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
			state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
			state[8 * 6 + i], state[8 * 7 + i]);
	}

	for (i = 0; i < ARGON2_OWORDS_IN_argon_block; i++) {
		state[i] = _mm_xor_si128(state[i], argon_block_XY[i]);
		_mm_storeu_si128((__m128i *)next_argon_block->v + i, state[i]);
	}
}



static void scopy_argon_block(argon_block *dst, const argon_block *src) {
	memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_argon_block);
}
static void scopy_argon_blockS(argon_blockS *dst, const argon_blockS *src) {
	memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_argon_block);
}
static void scopy_argon_blockS(argon_blockS *dst, const argon_block *src) {
	memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_argon_block);
}


#define VC_GE_2005(version) (version >= 1400)

static void  ssecure_wipe_memory(void *v, size_t n) {
#if defined(_MSC_VER) && VC_GE_2005(_MSC_VER)
	SecureZeroMemory(v, n);
#elif defined memset_s
	memset_s(v, n, 0, n);
#elif defined(__OpenBSD__)
	explicit_bzero(v, n);
#else
	static void *(*const volatile memset_sec)(void *, int, size_t) = &memset;
	memset_sec(v, 0, n);
#endif
}

/* Memory clear flag defaults to true. */

static void sclear_internal_memory(void *v, size_t n) {
	if (FLAG_clear_internal_memory && v) {
		ssecure_wipe_memory(v, n);
	}
}


static void sfree_memory(const argon2_context *context, uint8_t *memory,
	size_t num, size_t size) {
//	size_t memory_size = num*size;
	size_t memory_size = 128 * 8 * 2 * 4 * 2;
//	clear_internal_memory(memory, memory_size);
	if (context->free_cbk) {
		(context->free_cbk)(memory, memory_size);
	}
	else {
		free(memory);
	}
}

argon2_context init_argon2d_param(const char* input) {

#define TEST_OUTLEN 32
#define TEST_PWDLEN 80
#define TEST_SALTLEN 80
#define TEST_SECRETLEN 0
#define TEST_ADLEN 0
    argon2_context context;
    argon2_context *pContext = &context;

    unsigned char out[TEST_OUTLEN];
    //unsigned char pwd[TEST_PWDLEN];
    //unsigned char salt[TEST_SALTLEN]; 
	//    unsigned char secret[TEST_SECRETLEN];
	//   unsigned char ad[TEST_ADLEN];
    const allocate_fptr myown_allocator = NULL;
    const deallocate_fptr myown_deallocator = NULL;

    unsigned t_cost = 1;
    unsigned m_cost =  memcost; //2*1024*1024; //*1024; //+896*1024; //32768*1;
	
    unsigned lanes = 4;

    memset(pContext,0,sizeof(argon2_context));
    memset(&out[0], 0, sizeof(out));
    //memset(&pwd[0], nHeight + 1, TEST_OUTLEN);
    //memset(&salt[0], 2, TEST_SALTLEN);
    //memset(&secret[0], 3, TEST_SECRETLEN); 
    //memset(&ad[0], 4, TEST_ADLEN);

    context.out = out;
    context.outlen = TEST_OUTLEN;
    context.version = ARGON2_VERSION_NUMBER;
    context.pwd = (uint8_t*)input;
    context.pwdlen = TEST_PWDLEN;
    context.salt = (uint8_t*)input;
    context.saltlen = TEST_SALTLEN;
    context.secret = NULL;
    context.secretlen = TEST_SECRETLEN;
    context.ad = NULL;
    context.adlen = TEST_ADLEN;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = lanes;
    context.threads = lanes;
    context.allocate_cbk = myown_allocator;
    context.free_cbk = myown_deallocator;
    context.flags = ARGON2_DEFAULT_FLAGS;

#undef TEST_OUTLEN
#undef TEST_PWDLEN
#undef TEST_SALTLEN
#undef TEST_SECRETLEN
#undef TEST_ADLEN

    return context;
}



int mtp_solver_orig(uint32_t TheNonce, argon2_instance_t *instance,
	argon_blockS *nargon_blockMTP /*[72 * 2][128]*/,unsigned char* nProofMTP, unsigned char* resultMerkleRoot, unsigned char* mtpHashValue,
MerkleTree TheTree,uint32_t* input, uint256 hashTarget) {



	if (instance != NULL) {
//		input[19]=0x01000000;
		uint256 Y[L+1];
//		std::string proof_argon_blocks[L * 3];
		memset(&Y, 0, sizeof(Y));
		uint8_t zero[32] = {0};
		ablake2b_state BlakeHash;
		ablake2b_init(&BlakeHash, 32);
	
		uint32_t Test[4];

	for (int i = 0; i<4;i++)
			Test[i] = ((uint32_t*)resultMerkleRoot)[i];



		ablake2b_update(&BlakeHash, (unsigned char*)&input[0], 80);
		ablake2b_update(&BlakeHash, (unsigned char*)&resultMerkleRoot[0], 16);
		ablake2b_update(&BlakeHash, &TheNonce, sizeof(unsigned int));
		ablake2b_final(&BlakeHash, (unsigned char*)&Y[0], 32);



		argon_blockS argon_blocks[L * 2];
		
		///////////////////////////////
		bool init_argon_blocks = false;
		bool unmatch_argon_block = false;
		unsigned char proof_ser[1000]={0};
		unsigned int proof_size;
		for (uint8_t j = 1; j <= L; j++) {
 
			uint32_t ij = (((uint32_t*)(&Y[j - 1]))[0]) % (instance->context_ptr->m_cost );
			uint32_t except_index = (uint32_t)(instance->context_ptr->m_cost / instance->context_ptr->lanes);
			if (ij %except_index == 0 || ij%except_index == 1) {
				init_argon_blocks = true;
				break;
			}
 
			uint32_t prev_index;
			uint32_t ref_index;
			getargon_blockindex_orig(ij, instance, &prev_index, &ref_index);
 
			scopy_argon_blockS(&nargon_blockMTP[j * 2 - 2], &instance->memory[prev_index]);
			//ref argon_block
			scopy_argon_blockS(&nargon_blockMTP[j * 2 - 1], &instance->memory[ref_index]);

			argon_block argon_blockhash;
			uint8_t argon_blockhash_bytes[ARGON2_argon_block_SIZE];
			scopy_argon_block(&argon_blockhash, &instance->memory[ij]);

 
			sstore_argon_block(&argon_blockhash_bytes, &argon_blockhash);

			ablake2b_state BlakeHash2;
			ablake2b_init(&BlakeHash2, 32);
			ablake2b_update(&BlakeHash2, &Y[j - 1], sizeof(uint256));
			ablake2b_update(&BlakeHash2, argon_blockhash_bytes, ARGON2_argon_block_SIZE);
			ablake2b_final(&BlakeHash2, (unsigned char*)&Y[j], 32);
////////////////////////////////////////////////////////////////
// current argon_block

			unsigned char curr[32] = { 0 };
			argon_block argon_blockhash_curr;
			uint8_t argon_blockhash_curr_bytes[ARGON2_argon_block_SIZE];
			scopy_argon_block(&argon_blockhash_curr, &instance->memory[ij]);
			sstore_argon_block(&argon_blockhash_curr_bytes, &argon_blockhash_curr);
			ablake2b_state state_curr;
			ablake2b_init(&state_curr, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_curr, argon_blockhash_curr_bytes, ARGON2_argon_block_SIZE);
			uint8_t digest_curr[MERKLE_TREE_ELEMENT_SIZE_B];
			ablake2b4rounds_final(&state_curr, digest_curr, sizeof(digest_curr));
			MerkleTree::Buffer hash_curr = MerkleTree::Buffer(digest_curr, digest_curr + sizeof(digest_curr));
			sclear_internal_memory(argon_blockhash_curr.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_curr_bytes, ARGON2_argon_block_SIZE);


			std::deque<std::vector<uint8_t>> zProofMTP = TheTree.getProofOrdered(hash_curr, ij + 1);

			nProofMTP[(j * 3 - 3) * 353] = (unsigned char)(zProofMTP.size());

			int k1=0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP) {	
			std::copy(mtpData.begin(),mtpData.end(), nProofMTP +((j * 3 - 3) * 353 + 1 + k1 * mtpData.size()));
			k1++;
			}

			//prev proof
			unsigned char prev[32]={0};
			argon_block argon_blockhash_prev;
			uint8_t argon_blockhash_prev_bytes[ARGON2_argon_block_SIZE];
			scopy_argon_block(&argon_blockhash_prev, &instance->memory[prev_index]);
			sstore_argon_block(&argon_blockhash_prev_bytes, &argon_blockhash_prev);
			ablake2b_state state_prev;
			ablake2b_init(&state_prev, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_prev, argon_blockhash_prev_bytes, ARGON2_argon_block_SIZE);
			uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];


			ablake2b4rounds_final(&state_prev, digest_prev, sizeof(digest_prev));

 
			MerkleTree::Buffer hash_prev = MerkleTree::Buffer(digest_prev, digest_prev + sizeof(digest_prev));
			sclear_internal_memory(argon_blockhash_prev.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_prev_bytes, ARGON2_argon_block_SIZE);

			std::deque<std::vector<uint8_t>> zProofMTP2 = TheTree.getProofOrdered(hash_prev, prev_index + 1);

			nProofMTP[(j * 3 - 2) * 353] = (unsigned char)(zProofMTP2.size());

			int k2 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP2) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 2) * 353 + 1 + k2 * mtpData.size()));
				k2++;
			}


			//ref proof
			unsigned char ref[32] = { 0 };
			argon_block argon_blockhash_ref;
			uint8_t argon_blockhash_ref_bytes[ARGON2_argon_block_SIZE];
			scopy_argon_block(&argon_blockhash_ref, &instance->memory[ref_index]);
			sstore_argon_block(&argon_blockhash_ref_bytes, &argon_blockhash_ref);
			ablake2b_state state_ref;
			ablake2b_init(&state_ref, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_ref, argon_blockhash_ref_bytes, ARGON2_argon_block_SIZE);
			uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
			ablake2b4rounds_final(&state_ref, digest_ref, sizeof(digest_ref));
			MerkleTree::Buffer hash_ref = MerkleTree::Buffer(digest_ref, digest_ref + sizeof(digest_ref));
			sclear_internal_memory(argon_blockhash_ref.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_ref_bytes, ARGON2_argon_block_SIZE);

			std::deque<std::vector<uint8_t>> zProofMTP3 = TheTree.getProofOrdered(hash_ref, ref_index + 1);

			nProofMTP[(j * 3 - 1) * 353] = (unsigned char)(zProofMTP3.size());

			int k3 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP3) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 1) * 353 + 1 + k3 * mtpData.size()));
				k3++;
			}


/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
		}

		if (init_argon_blocks) {
 
			return 0;
		}

 
		char hex_tmp[64];
 
		if (Y[L] > hashTarget) {

		}
		else {
			for (int i=0;i<32;i++)
			mtpHashValue[i]= (((unsigned char*)(&Y[L]))[i]);

			// Found a solution
			printf("Found a solution. Nonce=%08x Hash:",TheNonce);
			for (int n = 0; n < 32; n++) {
				printf("%02x", ((unsigned char*)&Y[0])[n]);
			}
			printf("\n");
			return 1;


		}
 
	}
 

	return 0;
}



int mtp_solver(int thr_id, cl_command_queue Queue, cl_mem clblock, cl_mem clblock2, uint32_t TheNonce, argon2_instance_t *instance,
	argon_blockS *nargon_blockMTP /*[72 * 2][128]*/, unsigned char* nProofMTP, unsigned char* resultMerkleRoot, unsigned char* mtpHashValue,
	MerkleTree* zTheTree, uint32_t* input, uint256* zhashTarget) {


	MerkleTree TheTree = zTheTree[0];
	uint256 hashTarget = zhashTarget[0];

	if (instance != NULL) {
		//		input[19]=0x01000000;
		uint256 Y[L + 1];
		//		std::string proof_argon_blocks[L * 3];
		memset(&Y, 0, sizeof(Y));
		uint8_t zero[32] = { 0 };
		ablake2b_state BlakeHash;
		ablake2b_init(&BlakeHash, 32);




		ablake2b_update(&BlakeHash, (unsigned char*)&input[0], 80);
		ablake2b_update(&BlakeHash, (unsigned char*)&resultMerkleRoot[0], 16);
		ablake2b_update(&BlakeHash, &TheNonce, sizeof(unsigned int));
		ablake2b_final(&BlakeHash, (unsigned char*)&Y[0], 32);

		argon_blockS argon_blocks[L * 2];

		///////////////////////////////
		bool init_argon_blocks = false;
		bool unmatch_argon_block = false;
		unsigned char proof_ser[1000] = { 0 };
		unsigned int proof_size;
		for (uint8_t j = 1; j <= L; j++) {

			uint32_t ij = (((uint32_t*)(&Y[j - 1]))[0]) % (instance->context_ptr->m_cost);
			uint32_t except_index = (uint32_t)(instance->context_ptr->m_cost / instance->context_ptr->lanes);
			if (ij %except_index == 0 || ij%except_index == 1) {
				init_argon_blocks = true;
				break;
			}

			uint32_t prev_index;
			uint32_t ref_index;
			getargon_blockindex(thr_id, Queue, clblock, clblock2, ij, instance, &prev_index, &ref_index);

			//			copy_argon_blockS(&nargon_blockMTP[j * 2 - 2], &instance->memory[prev_index]);
			get_argon_block(/*thr_id,*/Queue,clblock, clblock2, (uint8_t*)nargon_blockMTP[j * 2 - 2].v, prev_index);
			//ref argon_block
			//			copy_argon_blockS(&nargon_blockMTP[j * 2 - 1], &instance->memory[ref_index]);
			get_argon_block(/*thr_id,*/Queue, clblock, clblock2, (uint8_t*)nargon_blockMTP[j * 2 - 1].v, ref_index);
			argon_block argon_blockhash;
			uint8_t argon_blockhash_bytes[ARGON2_argon_block_SIZE];
			//			copy_argon_block(&argon_blockhash, &instance->memory[ij]);
			get_argon_block(/*thr_id,*/Queue, clblock, clblock2, (uint8_t*)&argon_blockhash.v, ij);


			sstore_argon_block(&argon_blockhash_bytes, &argon_blockhash);

			ablake2b_state BlakeHash2;
			ablake2b_init(&BlakeHash2, 32);
			ablake2b_update(&BlakeHash2, &Y[j - 1], sizeof(uint256));
			ablake2b_update(&BlakeHash2, argon_blockhash_bytes, ARGON2_argon_block_SIZE);
			ablake2b_final(&BlakeHash2, (unsigned char*)&Y[j], 32);
			////////////////////////////////////////////////////////////////
			// current argon_block
			sclear_internal_memory(argon_blockhash.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_bytes, ARGON2_argon_block_SIZE);

			unsigned char curr[32] = { 0 };
			argon_block argon_blockhash_curr;
			uint8_t argon_blockhash_curr_bytes[ARGON2_argon_block_SIZE];
			//			copy_argon_block(&argon_blockhash_curr, &instance->memory[ij]);
			get_argon_block(/*thr_id,*/Queue, clblock, clblock2, (uint8_t*)&argon_blockhash_curr.v, ij);
			sstore_argon_block(&argon_blockhash_curr_bytes, &argon_blockhash_curr);
			ablake2b_state state_curr;
			ablake2b_init(&state_curr, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_curr, argon_blockhash_curr_bytes, ARGON2_argon_block_SIZE);
			uint8_t digest_curr[MERKLE_TREE_ELEMENT_SIZE_B];
			ablake2b4rounds_final(&state_curr, digest_curr, sizeof(digest_curr));
			MerkleTree::Buffer hash_curr = MerkleTree::Buffer(digest_curr, digest_curr + sizeof(digest_curr));
			sclear_internal_memory(argon_blockhash_curr.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_curr_bytes, ARGON2_argon_block_SIZE);


			std::deque<std::vector<uint8_t>> zProofMTP = TheTree.getProofOrdered(hash_curr, ij + 1);

			nProofMTP[(j * 3 - 3) * 353] = (unsigned char)(zProofMTP.size());

			int k1 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 3) * 353 + 1 + k1 * mtpData.size()));
				k1++;
			}

			//prev proof
			unsigned char prev[32] = { 0 };
			argon_block argon_blockhash_prev;
			uint8_t argon_blockhash_prev_bytes[ARGON2_argon_block_SIZE];
			//			copy_argon_block(&argon_blockhash_prev, &instance->memory[prev_index]);
			get_argon_block(/*thr_id,*/Queue, clblock, clblock2, (uint8_t*)&argon_blockhash_prev.v, prev_index);
			sstore_argon_block(&argon_blockhash_prev_bytes, &argon_blockhash_prev);
			ablake2b_state state_prev;
			ablake2b_init(&state_prev, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_prev, argon_blockhash_prev_bytes, ARGON2_argon_block_SIZE);
			uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];


			ablake2b4rounds_final(&state_prev, digest_prev, sizeof(digest_prev));


			MerkleTree::Buffer hash_prev = MerkleTree::Buffer(digest_prev, digest_prev + sizeof(digest_prev));
			sclear_internal_memory(argon_blockhash_prev.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_prev_bytes, ARGON2_argon_block_SIZE);

			std::deque<std::vector<uint8_t>> zProofMTP2 = TheTree.getProofOrdered(hash_prev, prev_index + 1);

			nProofMTP[(j * 3 - 2) * 353] = (unsigned char)(zProofMTP2.size());

			int k2 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP2) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 2) * 353 + 1 + k2 * mtpData.size()));
				k2++;
			}


			//ref proof
			unsigned char ref[32] = { 0 };
			argon_block argon_blockhash_ref;
			uint8_t argon_blockhash_ref_bytes[ARGON2_argon_block_SIZE];
			//			copy_argon_block(&argon_blockhash_ref, &instance->memory[ref_index]);
			get_argon_block(/*thr_id,*/Queue, clblock, clblock2, (uint8_t*)&argon_blockhash_ref.v, ref_index);
			sstore_argon_block(&argon_blockhash_ref_bytes, &argon_blockhash_ref);
			ablake2b_state state_ref;
			ablake2b_init(&state_ref, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_ref, argon_blockhash_ref_bytes, ARGON2_argon_block_SIZE);
			uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
			ablake2b4rounds_final(&state_ref, digest_ref, sizeof(digest_ref));
			MerkleTree::Buffer hash_ref = MerkleTree::Buffer(digest_ref, digest_ref + sizeof(digest_ref));
			sclear_internal_memory(argon_blockhash_ref.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_ref_bytes, ARGON2_argon_block_SIZE);

			std::deque<std::vector<uint8_t>> zProofMTP3 = TheTree.getProofOrdered(hash_ref, ref_index + 1);

			nProofMTP[(j * 3 - 1) * 353] = (unsigned char)(zProofMTP3.size());

			int k3 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP3) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 1) * 353 + 1 + k3 * mtpData.size()));
				k3++;
			}


			/////////////////////////////////////////////////////////////////////
			/////////////////////////////////////////////////////////////////////
		}

		if (init_argon_blocks) {

			return 0;
		}


		char hex_tmp[64];

		if (Y[L] > hashTarget) {

		}
		else {
			for (int i = 0; i<32; i++)
				mtpHashValue[i] = (((unsigned char*)(&Y[L]))[i]);

			// Found a solution
/*
			printf("Found a solution. Nonce=%08x Hash:", TheNonce);
			for (int n = 0; n < 32; n++) {
				printf("%02x", ((unsigned char*)&Y[0])[n]);
			}
			printf("\n");
*/
			return 1;


		}

	}


	return 0;
}




int mtp_solver_short(int thr_id, cl_command_queue Queue, cl_mem clblock, uint32_t TheNonce, argon2_instance_t *instance,
	argon_blockS *nargon_blockMTP /*[72 * 2][128]*/, unsigned char* nProofMTP, unsigned char* resultMerkleRoot, unsigned char* mtpHashValue,
	MerkleTree* zTheTree, uint32_t* input, uint256* zhashTarget) {


	MerkleTree TheTree = zTheTree[0];
	uint256 hashTarget = zhashTarget[0];

	if (instance != NULL) {
		//		input[19]=0x01000000;
		uint256 Y[L + 1];
		//		std::string proof_argon_blocks[L * 3];
		memset(&Y, 0, sizeof(Y));
		uint8_t zero[32] = { 0 };
		ablake2b_state BlakeHash;
		ablake2b_init(&BlakeHash, 32);




		ablake2b_update(&BlakeHash, (unsigned char*)&input[0], 80);
		ablake2b_update(&BlakeHash, (unsigned char*)&resultMerkleRoot[0], 16);
		ablake2b_update(&BlakeHash, &TheNonce, sizeof(unsigned int));
		ablake2b_final(&BlakeHash, (unsigned char*)&Y[0], 32);

		argon_blockS argon_blocks[L * 2];

		///////////////////////////////
		bool init_argon_blocks = false;
		bool unmatch_argon_block = false;
		unsigned char proof_ser[1000] = { 0 };
		unsigned int proof_size;
		for (uint8_t j = 1; j <= L; j++) {

			uint32_t ij = (((uint32_t*)(&Y[j - 1]))[0]) % (instance->context_ptr->m_cost);
			uint32_t except_index = (uint32_t)(instance->context_ptr->m_cost / instance->context_ptr->lanes);
			if (ij %except_index == 0 || ij%except_index == 1) {
				init_argon_blocks = true;
				break;
			}

			uint32_t prev_index;
			uint32_t ref_index;
			getargon_blockindex_short(thr_id, Queue, clblock,  ij, instance, &prev_index, &ref_index);

			//			copy_argon_blockS(&nargon_blockMTP[j * 2 - 2], &instance->memory[prev_index]);
			get_argon_block_short(/*thr_id,*/Queue, clblock, (uint8_t*)nargon_blockMTP[j * 2 - 2].v, prev_index);
			//ref argon_block
			//			copy_argon_blockS(&nargon_blockMTP[j * 2 - 1], &instance->memory[ref_index]);
			get_argon_block_short(/*thr_id,*/Queue, clblock,  (uint8_t*)nargon_blockMTP[j * 2 - 1].v, ref_index);
			argon_block argon_blockhash;
			uint8_t argon_blockhash_bytes[ARGON2_argon_block_SIZE];
			//			copy_argon_block(&argon_blockhash, &instance->memory[ij]);
			get_argon_block_short(/*thr_id,*/Queue, clblock,  (uint8_t*)&argon_blockhash.v, ij);


			sstore_argon_block(&argon_blockhash_bytes, &argon_blockhash);

			ablake2b_state BlakeHash2;
			ablake2b_init(&BlakeHash2, 32);
			ablake2b_update(&BlakeHash2, &Y[j - 1], sizeof(uint256));
			ablake2b_update(&BlakeHash2, argon_blockhash_bytes, ARGON2_argon_block_SIZE);
			ablake2b_final(&BlakeHash2, (unsigned char*)&Y[j], 32);
			////////////////////////////////////////////////////////////////
			// current argon_block
			sclear_internal_memory(argon_blockhash.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_bytes, ARGON2_argon_block_SIZE);

			unsigned char curr[32] = { 0 };
			argon_block argon_blockhash_curr;
			uint8_t argon_blockhash_curr_bytes[ARGON2_argon_block_SIZE];
			//			copy_argon_block(&argon_blockhash_curr, &instance->memory[ij]);
			get_argon_block_short(/*thr_id,*/Queue, clblock,  (uint8_t*)&argon_blockhash_curr.v, ij);
			sstore_argon_block(&argon_blockhash_curr_bytes, &argon_blockhash_curr);
			ablake2b_state state_curr;
			ablake2b_init(&state_curr, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_curr, argon_blockhash_curr_bytes, ARGON2_argon_block_SIZE);
			uint8_t digest_curr[MERKLE_TREE_ELEMENT_SIZE_B];
			ablake2b4rounds_final(&state_curr, digest_curr, sizeof(digest_curr));
			MerkleTree::Buffer hash_curr = MerkleTree::Buffer(digest_curr, digest_curr + sizeof(digest_curr));
			sclear_internal_memory(argon_blockhash_curr.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_curr_bytes, ARGON2_argon_block_SIZE);


			std::deque<std::vector<uint8_t>> zProofMTP = TheTree.getProofOrdered(hash_curr, ij + 1);

			nProofMTP[(j * 3 - 3) * 353] = (unsigned char)(zProofMTP.size());

			int k1 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 3) * 353 + 1 + k1 * mtpData.size()));
				k1++;
			}

			//prev proof
			unsigned char prev[32] = { 0 };
			argon_block argon_blockhash_prev;
			uint8_t argon_blockhash_prev_bytes[ARGON2_argon_block_SIZE];
			//			copy_argon_block(&argon_blockhash_prev, &instance->memory[prev_index]);
			get_argon_block_short(/*thr_id,*/Queue, clblock,  (uint8_t*)&argon_blockhash_prev.v, prev_index);
			sstore_argon_block(&argon_blockhash_prev_bytes, &argon_blockhash_prev);
			ablake2b_state state_prev;
			ablake2b_init(&state_prev, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_prev, argon_blockhash_prev_bytes, ARGON2_argon_block_SIZE);
			uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];


			ablake2b4rounds_final(&state_prev, digest_prev, sizeof(digest_prev));


			MerkleTree::Buffer hash_prev = MerkleTree::Buffer(digest_prev, digest_prev + sizeof(digest_prev));
			sclear_internal_memory(argon_blockhash_prev.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_prev_bytes, ARGON2_argon_block_SIZE);

			std::deque<std::vector<uint8_t>> zProofMTP2 = TheTree.getProofOrdered(hash_prev, prev_index + 1);

			nProofMTP[(j * 3 - 2) * 353] = (unsigned char)(zProofMTP2.size());

			int k2 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP2) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 2) * 353 + 1 + k2 * mtpData.size()));
				k2++;
			}


			//ref proof
			unsigned char ref[32] = { 0 };
			argon_block argon_blockhash_ref;
			uint8_t argon_blockhash_ref_bytes[ARGON2_argon_block_SIZE];
			//			copy_argon_block(&argon_blockhash_ref, &instance->memory[ref_index]);
			get_argon_block_short(/*thr_id,*/Queue, clblock, (uint8_t*)&argon_blockhash_ref.v, ref_index);
			sstore_argon_block(&argon_blockhash_ref_bytes, &argon_blockhash_ref);
			ablake2b_state state_ref;
			ablake2b_init(&state_ref, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_ref, argon_blockhash_ref_bytes, ARGON2_argon_block_SIZE);
			uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
			ablake2b4rounds_final(&state_ref, digest_ref, sizeof(digest_ref));
			MerkleTree::Buffer hash_ref = MerkleTree::Buffer(digest_ref, digest_ref + sizeof(digest_ref));
			sclear_internal_memory(argon_blockhash_ref.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_ref_bytes, ARGON2_argon_block_SIZE);

			std::deque<std::vector<uint8_t>> zProofMTP3 = TheTree.getProofOrdered(hash_ref, ref_index + 1);

			nProofMTP[(j * 3 - 1) * 353] = (unsigned char)(zProofMTP3.size());

			int k3 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP3) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 1) * 353 + 1 + k3 * mtpData.size()));
				k3++;
			}


			/////////////////////////////////////////////////////////////////////
			/////////////////////////////////////////////////////////////////////
		}

		if (init_argon_blocks) {

			return 0;
		}


		char hex_tmp[64];

		if (Y[L] > hashTarget) {

		}
		else {
			for (int i = 0; i<32; i++)
				mtpHashValue[i] = (((unsigned char*)(&Y[L]))[i]);

			// Found a solution
			/*
			printf("Found a solution. Nonce=%08x Hash:", TheNonce);
			for (int n = 0; n < 32; n++) {
			printf("%02x", ((unsigned char*)&Y[0])[n]);
			}
			printf("\n");
			*/
			return 1;


		}

	}


	return 0;
}




MerkleTree::Elements mtp_init( argon2_instance_t *instance) {
	//internal_kat(instance, r); /* Print all memory argon_blocks */
	printf("Step 1 : Compute F(I) and store its T argon_blocks X[1], X[2], ..., X[T] in the memory \n");
	// Step 1 : Compute F(I) and store its T argon_blocks X[1], X[2], ..., X[T] in the memory
	
	MerkleTree::Elements elements;
	if (instance != NULL) {
		printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");
		//		vector<char*> leaves((instance->context_ptr->m_cost)); // 2gb
	
		for (int i = 0; i < instance->memory_argon_blocks; ++i) {
			argon_block argon_blockhash;
			uint8_t argon_blockhash_bytes[ARGON2_argon_block_SIZE];
			scopy_argon_block(&argon_blockhash, &instance->memory[i]);
			sstore_argon_block(&argon_blockhash_bytes, &argon_blockhash);

//			uint512 hashargon_block;
			ablake2b_state ctx;
			ablake2b_init(&ctx, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&ctx, argon_blockhash_bytes, ARGON2_argon_block_SIZE);
			uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
			ablake2b4rounds_final(&ctx, digest, sizeof(digest));
			MerkleTree::Buffer hash_digest = MerkleTree::Buffer(digest, digest + sizeof(digest));
			elements.push_back(hash_digest);

			sclear_internal_memory(argon_blockhash.v, ARGON2_argon_block_SIZE);
			sclear_internal_memory(argon_blockhash_bytes, ARGON2_argon_block_SIZE);

		}
/*
		MerkleTree ordered_tree(elements, true);

		MerkleTree::Buffer root = ordered_tree.getRoot();
		std::copy(root.begin(), root.end(), resultMerkleRoot);
*/

		printf("end Step 2 : Compute the root Φ of the Merkle hash tree \n");
		return elements;
	}

	

}

MerkleTree::Elements   mtp_init2(argon2_instance_t *instance) {

	MerkleTree::Elements  elements;
	printf("Step 1 : Compute F(I) and store its T argon_blocks X[1], X[2], ..., X[T] in the memory \n");
	//	MerkleTree::Elements elements;
	if (instance != NULL) {
		printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");
		uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
		for (int i = 0; i < instance->memory_argon_blocks / 2; ++i) {
			memset(digest, 0, MERKLE_TREE_ELEMENT_SIZE_B);
			compute_blake2b(instance->memory[2 * i], digest);
			elements.emplace_back(digest, digest + sizeof(digest));
			memset(digest, 0, MERKLE_TREE_ELEMENT_SIZE_B);
			compute_blake2b(instance->memory[2 * i + 1], digest);
			elements.emplace_back(digest, digest + sizeof(digest));
			//			elements->push_back(digest, digest + sizeof(digest));
		}

		printf("end Step 2 : Compute the root Φ of the Merkle hash tree \n");
		return elements;
	}

}

void  mtp_init3(argon2_instance_t *instance, int thr_id, MerkleTree &ThatTree) {

	printf("Step 1 : Compute F(I) and store its T argon_blocks X[1], X[2], ..., X[T] in the memory \n");
//	uint8_t *mem = (uint8_t*)malloc(MERKLE_TREE_ELEMENT_SIZE_B*instance->memory_argon_blocks);
//	get_tree(thr_id);
	printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");

//	ThatTree = MerkleTree(get_tree2(thr_id),true);
//	ThatTree = TheTree;
//	free(mem);
}

//
void mtp_hash(char* output, const char* input, unsigned int d,uint32_t TheNonce) {
    argon2_context context = init_argon2d_param(input);
    argon2_instance_t instance;
    argon2_ctx_from_mtp(&context, &instance);
//    mtp_prover(TheNonce, &instance, d, output);
//    free_memory(&context, (uint8_t *)instance.memory, instance.memory_argon_blocks, sizeof(argon_block));

}
