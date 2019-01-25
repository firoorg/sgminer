
/**
* MTP
* djm34 2017-2018
* krnlx 2018
**/

typedef unsigned long uint64_t;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

/*static */ uint32_t *h_MinNonces[16]; // this need to get fixed as the rest of that routine
/*static*/ uint32_t *d_MinNonces[16];

__constant__ uint32_t pTarget[8];
__constant__ uint32_t pData[20]; // truncated data
__constant__ uint4 Elements[1];
uint4 * HBlock[16];
/*__device__*/ uint32_t *Header[16];
/*__device__*/ uint2 *buffer_a[16];

#define ARGON2_SYNC_POINTS 4
#define argon_outlen 32
#define argon_timecost 1
#define argon_memcost 4*1024*1024 // *1024 //32*1024*2 //1024*256*1 //2Gb
#define argon_lanes 4
#define argon_threads 1
#define argon_hashlen 80
#define argon_version 19
#define argon_type 0 // argon2d
#define argon_pwdlen 80 // hash and salt lenght
#define argon_default_flags 0 // hmm not sure
#define argon_segment_length argon_memcost/(argon_lanes * ARGON2_SYNC_POINTS)
#define argon_lane_length argon_segment_length * ARGON2_SYNC_POINTS
#define TREE_LEVELS 20
#define ELEM_MAX 2048
#define gpu_thread 2
#define gpu_shared 128
#define kernel1_thread 64
#define mtp_L 64
#define TPB52 32
#define TPB30 160
#define TPB20 160

__constant const uint2 blakeInit[8] =
{
	( 0xf2bdc948UL, 0x6a09e667UL ),
	( 0x84caa73bUL, 0xbb67ae85UL ),
	( 0xfe94f82bUL, 0x3c6ef372UL ),
	( 0x5f1d36f1UL, 0xa54ff53aUL ),
	( 0xade682d1UL, 0x510e527fUL ),
	( 0x2b3e6c1fUL, 0x9b05688cUL ),
	( 0xfb41bd6bUL, 0x1f83d9abUL ),
	( 0x137e2179UL, 0x5be0cd19UL )
};

__constant const uint2 blakeFinal[8] =
{
	( 0xf2bdc928UL, 0x6a09e667UL ),
	( 0x84caa73bUL, 0xbb67ae85UL ),
	( 0xfe94f82bUL, 0x3c6ef372UL ),
	( 0x5f1d36f1UL, 0xa54ff53aUL ),
	( 0xade682d1UL, 0x510e527fUL ),
	( 0x2b3e6c1fUL, 0x9b05688cUL ),
	( 0xfb41bd6bUL, 0x1f83d9abUL ),
	( 0x137e2179UL, 0x5be0cd19UL )
};

__constant const uint2 blakeIV[8] =
{
	( 0xf3bcc908UL, 0x6a09e667UL ),
	( 0x84caa73bUL, 0xbb67ae85UL ),
	( 0xfe94f82bUL, 0x3c6ef372UL ),
	( 0x5f1d36f1UL, 0xa54ff53aUL ),
	( 0xade682d1UL, 0x510e527fUL ),
	( 0x2b3e6c1fUL, 0x9b05688cUL ),
	( 0xfb41bd6bUL, 0x1f83d9abUL ),
	( 0x137e2179UL, 0x5be0cd19UL )
};

__constant const uint2 blakeInit2[8] =
{
	( 0xf2bdc918UL, 0x6a09e667UL ),
	( 0x84caa73bUL, 0xbb67ae85UL ),
	( 0xfe94f82bUL, 0x3c6ef372UL ),
	( 0x5f1d36f1UL, 0xa54ff53aUL ),
	( 0xade682d1UL, 0x510e527fUL ),
	( 0x2b3e6c1fUL, 0x9b05688cUL ),
	( 0xfb41bd6bUL, 0x1f83d9abUL ),
	( 0x137e2179UL, 0x5be0cd19UL )
};


/*__device__ __forceinline__*/
static uint64_t ROTR64X(const uint64_t value, const int offset) {
	uint2 result;
	const uint2 tmp = vectorize(value);

	if (offset == 8) {
		result.x = __byte_perm(tmp.x, tmp.y, 0x4321);
		result.y = __byte_perm(tmp.y, tmp.x, 0x4321);
	}
	else if (offset == 16) {
		result.x = __byte_perm(tmp.x, tmp.y, 0x5432);
		result.y = __byte_perm(tmp.y, tmp.x, 0x5432);
	}
	else if (offset == 24) {
		result.x = __byte_perm(tmp.x, tmp.y, 0x6543);
		result.y = __byte_perm(tmp.y, tmp.x, 0x6543);
	}
	else if (offset < 32) {
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(tmp.x), "r"(tmp.y), "r"(offset));
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.y) : "r"(tmp.y), "r"(tmp.x), "r"(offset));
	}
	else {
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.x) : "r"(tmp.y), "r"(tmp.x), "r"(offset));
		asm("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(result.y) : "r"(tmp.x), "r"(tmp.y), "r"(offset));
	}
	return devectorize(result);
}

__constant static const uint8_t blake2b_sigma[12][16] =
{
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
	{ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
	{ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
	{ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
	{ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};


/*
#define GS(a,b,c,d,e,f) \
{ \
v[a] +=   v[b] + m[e]; \
v[d] = eorswap32(v[d] , v[a]); \
v[c] += v[d]; \
v[b] = ROR2(v[b] ^ v[c], 24); \
v[a] += v[b] + m[f]; \
v[d] = ROR16(v[d] ^ v[a]); \
v[c] += v[d]; \
v[b] = ROR2(v[b] ^ v[c], 63); \
}
*/


#define GS(a,b,c,d,e,f) \
   { \
     v[a] +=   v[b] + m[e]; \
     v[d] = eorswap64(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 24); \
     v[a] += v[b] + m[f]; \
     v[d] = ROTR64X(v[d] ^ v[a], 16); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 63); \
  } 


#define ROUND0\
  { \
    GS(0,4,8,12,0,1); \
    GS(1,5,9,13,2,3 ); \
    GS(2,6,10,14,4,5); \
    GS(3,7,11,15,6,7); \
    GS(0,5,10,15,8,9); \
    GS(1,6,11,12,10,11); \
    GS(2,7,8,13,12,13); \
    GS(3,4,9,14,14,15); \
  }

#define ROUND1\
  { \
    GS(0,4,8,12,14,10); \
    GS(1,5,9,13,4,8 ); \
    GS(2,6,10,14,9,15); \
    GS(3,7,11,15,13,6); \
    GS(0,5,10,15,1,12); \
    GS(1,6,11,12,0,2); \
    GS(2,7,8,13,11,7); \
    GS(3,4,9,14,5,3); \
  }

#define ROUND2\
  { \
    GS(0,4,8,12,11,8); \
    GS(1,5,9,13,12,0 ); \
    GS(2,6,10,14,5,2); \
    GS(3,7,11,15,15,13); \
    GS(0,5,10,15,10,14); \
    GS(1,6,11,12,3,6); \
    GS(2,7,8,13,7,1); \
    GS(3,4,9,14,9,4); \
  }

#define ROUND3\
  { \
    GS(0,4,8,12,7,9); \
    GS(1,5,9,13,3,1 ); \
    GS(2,6,10,14,13,12); \
    GS(3,7,11,15,11,14); \
    GS(0,5,10,15,2,6); \
    GS(1,6,11,12,5,10); \
    GS(2,7,8,13,4,0); \
    GS(3,4,9,14,15,8); \
  }

#define ROUND4\
  { \
    GS(0,4,8,12,9,0); \
    GS(1,5,9,13,5,7 ); \
    GS(2,6,10,14,2,4); \
    GS(3,7,11,15,10,15); \
    GS(0,5,10,15,14,1); \
    GS(1,6,11,12,11,12); \
    GS(2,7,8,13,6,8); \
    GS(3,4,9,14,3,13); \
  }

#define ROUND5\
  { \
    GS(0,4,8,12,2,12); \
    GS(1,5,9,13,6,10 ); \
    GS(2,6,10,14,0,11); \
    GS(3,7,11,15,8,3); \
    GS(0,5,10,15,4,13); \
    GS(1,6,11,12,7,5); \
    GS(2,7,8,13,15,14); \
    GS(3,4,9,14,1,9); \
  }

#define ROUND6\
  { \
    GS(0,4,8,12,12,5); \
    GS(1,5,9,13,1,15 ); \
    GS(2,6,10,14,14,13); \
    GS(3,7,11,15,4,10); \
    GS(0,5,10,15,0,7); \
    GS(1,6,11,12,6,3); \
    GS(2,7,8,13,9,2); \
    GS(3,4,9,14,8,11); \
  }


#define ROUND7\
  { \
    GS(0,4,8,12,13,11); \
    GS(1,5,9,13,7,14 ); \
    GS(2,6,10,14,12,1); \
    GS(3,7,11,15,3,9); \
    GS(0,5,10,15,5,0); \
    GS(1,6,11,12,15,4); \
    GS(2,7,8,13,8,6); \
    GS(3,4,9,14,2,10); \
  }


#define ROUND8\
  { \
    GS(0,4,8,12,6,15); \
    GS(1,5,9,13,14,9 ); \
    GS(2,6,10,14,11,3); \
    GS(3,7,11,15,0,8); \
    GS(0,5,10,15,12,2); \
    GS(1,6,11,12,13,7); \
    GS(2,7,8,13,1,4); \
    GS(3,4,9,14,10,5); \
  }

#define ROUND9\
  { \
    GS(0,4,8,12,10,2); \
    GS(1,5,9,13,8,4 ); \
    GS(2,6,10,14,7,6); \
    GS(3,7,11,15,1,5); \
    GS(0,5,10,15,15,11); \
    GS(1,6,11,12,9,14); \
    GS(2,7,8,13,3,12); \
    GS(3,4,9,14,13,0); \
  }

#define ROUND10\
  { \
    GS(0,4,8,12,0,1); \
    GS(1,5,9,13,2,3 ); \
    GS(2,6,10,14,4,5); \
    GS(3,7,11,15,6,7); \
    GS(0,5,10,15,8,9); \
    GS(1,6,11,12,10,11); \
    GS(2,7,8,13,12,13); \
    GS(3,4,9,14,14,15); \
  }

#define ROUND11\
  { \
    GS(0,4,8,12,14,10); \
    GS(1,5,9,13,4,8 ); \
    GS(2,6,10,14,9,15); \
    GS(3,7,11,15,13,6); \
    GS(0,5,10,15,1,12); \
    GS(1,6,11,12,0,2); \
    GS(2,7,8,13,11,7); \
    GS(3,4,9,14,5,3); \
  }



static /*__device__ __forceinline__*/ uint2 eorswap32(uint2 u, uint2 v) {
	uint2 result;
	result.y = u.x ^ v.x;
	result.x = u.y ^ v.y;
	return result;
}

static /*__device__ __forceinline__*/ uint64_t eorswap64(uint64_t u, uint64_t v) {
	return ROTR64X(u^v, 32);
}

/*__device__ */ static int blake2b_compress4x(uint2 *hash, const uint2 *hzcash, const uint2 block[16], const uint32_t len, int last)
{
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	uint2 m[16];
	uint2 v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];

	uint64_t xv = last ? (uint64_t)-1 : 0;
	uint2 xv2 = vectorize(xv);
	v[8] = blakeIV[0];
	v[9] = blakeIV[1];
	v[10] = blakeIV[2];
	v[11] = blakeIV[3];
	v[12] = blakeIV[4];
	v[12].x ^= len;
	v[13] = blakeIV[5];
	v[14] = blakeIV[6] ^ xv2;
	v[15] = blakeIV[7];

	uint64_t *d = (uint64_t*)v;

#define G(r,i,a,b,c,d) \
   { \
     v[a] +=   v[b] + m[blake2b_sigma[r][2*i+0]]; \
     v[d] = eorswap32(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROR2(v[b] ^ v[c], 24); \
     v[a] += v[b] + m[blake2b_sigma[r][2*i+1]]; \
     v[d] = ROR16(v[d] ^ v[a]); \
     v[c] += v[d]; \
     v[b] = ROR2(v[b] ^ v[c], 63); \
  } 
#define ROUND(r)  \
  { \
    G(r,0, 0,4,8,12); \
    G(r,1, 1,5,9,13); \
    G(r,2, 2,6,10,14); \
    G(r,3, 3,7,11,15); \
    G(r,4, 0,5,10,15); \
    G(r,5, 1,6,11,12); \
    G(r,6, 2,7,8,13); \
    G(r,7, 3,4,9,14); \
  } 

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);

	for (int i = 0; i < 8; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];


#undef G
#undef ROUND
	return 0;
}



/*__device__ __forceinline__*/ uint32_t index_alpha(const uint32_t pass, const uint32_t slice, const uint32_t index,
	uint32_t pseudo_rand,
	int same_lane, const uint32_t ss, const uint32_t ss1) {

	uint32_t reference_area_size;
	uint64_t relative_position;
	uint32_t start_position, absolute_position;
	uint32_t lane_length = 1048576;
	uint32_t segment_length = 262144;
	uint32_t lanes = 4;

	if (0 == pass) {

		if (0 == slice) {

			reference_area_size =
				index - 1; 
		}
		else {
			if (same_lane) {

				reference_area_size =
					ss +
					index - 1;
			}
			else {
				reference_area_size =
					ss +
					((index == 0) ? (-1) : 0);
			}
		}
	}
	else {

		if (same_lane) {
			reference_area_size = lane_length -
				segment_length + index -
				1;
		}
		else {
			reference_area_size = lane_length -
				segment_length +
				((index == 0) ? (-1) : 0);
		}
	}

	relative_position = pseudo_rand;

	relative_position = _HIDWORD(relative_position * relative_position);

	relative_position = reference_area_size - 1 -
		_HIDWORD(reference_area_size * relative_position);

	start_position = 0;

	if (0 != pass) {
		start_position = (slice == ARGON2_SYNC_POINTS - 1)
			? 0
			: (ss1);
	}

	absolute_position = (start_position + relative_position) & 0xFFFFF;
	return absolute_position;
}

struct mem_blk {
	uint64_t v[128];
};


/*__device__ __forceinline__*/ void copy_block(mem_blk *dst, const mem_blk *src) {
	dst->v[threadIdx.x] = src->v[threadIdx.x];
	dst->v[threadIdx.x + 32] = src->v[threadIdx.x + 32];
	dst->v[threadIdx.x + 64] = src->v[threadIdx.x + 64];
	dst->v[threadIdx.x + 96] = src->v[threadIdx.x + 96];

}

/*__device__ __forceinline__*/ void xor_block(mem_blk *dst, const mem_blk *src) {
	dst->v[threadIdx.x] ^= src->v[threadIdx.x];
	dst->v[threadIdx.x + 32] ^= src->v[threadIdx.x + 32];
	dst->v[threadIdx.x + 64] ^= src->v[threadIdx.x + 64];
	dst->v[threadIdx.x + 96] ^= src->v[threadIdx.x + 96];
}
/*__device__ __forceinline__*/ uint64_t fBlaMka(uint64_t x, uint64_t y) {
	const uint64_t m = UINT64_C(0xFFFFFFFF);
	const uint64_t xy = ((uint64_t)_LODWORD(x) * (uint64_t)_LODWORD(y));
	return x + y + 2 * xy;
}

#define G(a, b, c, d)                                                          \
    do {                                                                       \
        a = fBlaMka(a, b);                                                     \
        d = SWAPDWORDS(d ^ a);                                                 \
        c = fBlaMka(c, d);                                                     \
        b = ROTR64X(b ^ c, 24);                                                 \
        a = fBlaMka(a, b);                                                     \
        d = ROTR64X(d ^ a, 16);                                                 \
        c = fBlaMka(c, d);                                                     \
        b = ROTR64X(b ^ c, 63);                                                 \
    } while ((void)0, 0)

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,   \
                           v12, v13, v14, v15)                                 \
    do {                                                                       \
        G(v0, v4, v8, v12);                                                    \
        G(v1, v5, v9, v13);                                                    \
        G(v2, v6, v10, v14);                                                   \
        G(v3, v7, v11, v15);                                                   \
        G(v0, v5, v10, v15);                                                   \
        G(v1, v6, v11, v12);                                                   \
        G(v2, v7, v8, v13);                                                    \
        G(v3, v4, v9, v14);                                                    \
    } while ((void)0, 0)

/*__device__ __forceinline__*/ void xor_copy_block(mem_blk *dst, const mem_blk *src, const mem_blk *src1) {
	dst->v[threadIdx.x] = src->v[threadIdx.x] ^ src1->v[threadIdx.x];
	dst->v[threadIdx.x + 32] = src->v[threadIdx.x + 32] ^ src1->v[threadIdx.x + 32];
	dst->v[threadIdx.x + 64] = src->v[threadIdx.x + 64] ^ src1->v[threadIdx.x + 64];
	dst->v[threadIdx.x + 96] = src->v[threadIdx.x + 96] ^ src1->v[threadIdx.x + 96];
}

/*__device__ __forceinline__*/ void dup_xor_copy_block(mem_blk *dst, mem_blk *dst1, const mem_blk *src, const mem_blk *src1) {
	dst1->v[threadIdx.x] = dst->v[threadIdx.x] = src->v[threadIdx.x] ^ src1->v[threadIdx.x];
}

/*__device__ __forceinline__*/ void fill_block_withIndex(const mem_blk *prev_block, const mem_blk *ref_block,
	mem_blk *next_block, int with_xor, uint32_t block_header[8], uint32_t index) {
	__shared__ mem_blk blockR;
	__shared__ mem_blk block_tmp;
	int tid = threadIdx.x;
	uint32_t TheIndex[2] = { 0,index };
	unsigned i;

	copy_block(&blockR, ref_block);

	xor_block(&blockR, prev_block);

	copy_block(&block_tmp, &blockR);

	if (with_xor) 
		xor_block(&block_tmp, next_block);

	if (!tid) 
		blockR.v[14] = MAKE_ULONGLONG(TheIndex[0], TheIndex[1]);

	

	uint32_t *bl = (uint32_t*)&blockR.v[16];

	if (!tid)
		for (int i = 0; i<8; i++)
			bl[i] = block_header[i];


	__syncwarp();

	{

		int i = tid;
		int y = (tid >> 2) << 4;
		int x = tid & 3;


		G(blockR.v[y + x], blockR.v[y + 4 + x], blockR.v[y + 8 + x], blockR.v[y + 12 + x]);
		G(blockR.v[y + x], blockR.v[y + 4 + ((1 + x) & 3)], blockR.v[y + 8 + ((2 + x) & 3)], blockR.v[y + 12 + ((3 + x) & 3)]);

	}
	__syncwarp();

	{

		int i = tid;
		int y = (tid >> 2) << 1;
		int x = tid & 3;
		int a = ((x) >> 1) * 16;
		int b = x & 1;

		int a1 = (((x + 1) & 3) >> 1) * 16;
		int b1 = (x + 1) & 1;

		int a2 = (((x + 2) & 3) >> 1) * 16;
		int b2 = (x + 2) & 1;

		int a3 = (((x + 3) & 3) >> 1) * 16;
		int b3 = (x + 3) & 1;

		G(blockR.v[y + b + a], blockR.v[y + 32 + b + a], blockR.v[y + 64 + b + a], blockR.v[y + 96 + b + a]);
		G(blockR.v[y + b + a], blockR.v[y + 32 + b1 + a1], blockR.v[y + 64 + b2 + a2], blockR.v[y + 96 + a3 + b3]);

	}
	__syncwarp();

	xor_copy_block(next_block, &block_tmp, &blockR);

}

//template <const uint32_t slice>
//__global__ __launch_bounds__(128, 1)


__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void mtp_i(uint4  *  DBlock, uint32_t *block_header, uint32_t slice) {
	uint32_t prev_offset, curr_offset;

	uint64_t  ref_index, ref_lane;
	const uint32_t pass = 0;

	uint32_t lane = blockIdx.x;
	const uint32_t lane_length = 1048576;
	const uint32_t segment_length = 262144;
	const uint32_t lanes = 4;
	uint32_t index;
	struct mem_blk * memory = (struct mem_blk *)DBlock;
	int tid = threadIdx.x;
	struct mem_blk *ref_block = NULL, *curr_block = NULL;
	uint32_t BH[8];
	uint32_t ss = slice * segment_length;
	uint32_t ss1 = (slice + 1) * segment_length;

	for (int i = 0; i<8; i++)
		BH[i] = block_header[i];

	uint32_t starting_index = 0;

	if ((0 == pass) && (0 == slice)) {
		starting_index = 2; 
	}
	curr_offset = lane * lane_length +
		slice * segment_length + starting_index;

	if (0 == curr_offset % lane_length) {
	
		prev_offset = curr_offset + lane_length - 1;
	}
	else {

		prev_offset = curr_offset - 1;
	}


	int truc = 0;
	uint64_t TheBlockIndex;
#pragma unroll 1
	for (int i = starting_index; i < segment_length;
		++i, ++curr_offset, ++prev_offset) {
		truc++;

		if (curr_offset & 0xFFFFF == 1) {
			prev_offset = curr_offset - 1;
		}

		uint2  pseudo_rand2 = vectorize(memory[prev_offset].v[0]);

		ref_lane = ((pseudo_rand2.y)) & 3;

		if ((pass == 0) && (slice == 0)) 
			ref_lane = lane;

		index = i;
		ref_index = index_alpha(pass, slice, index, pseudo_rand2.x,
			ref_lane == lane, ss, ss1);

		ref_block =
			memory + (ref_lane << 20) + ref_index;

		curr_block = memory + curr_offset;
		TheBlockIndex = (ref_lane << 20) + ref_index;

		fill_block_withIndex(memory + prev_offset, ref_block, curr_block, 0, BH, TheBlockIndex);

	}

}


__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void mtp_fc(uint32_t threads, uint4  *  DBlock, uint2 *a) {
	uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	if (thread < threads) {
		struct mem_blk * memory = (struct mem_blk *)DBlock;
		const uint4 *    __restrict__ GBlock = &DBlock[0];
		uint32_t len = 0;
		uint2 DataTmp[8];
		for (int i = 0; i<8; i++)
			DataTmp[i] = blakeInit2[i];
		for (int i = 0; i < 8; i++) {
			//              len += (i&1!=0)? 32:128;
			len += 128;
			uint16 DataChunk[2];
			DataChunk[0].lo = ((uint8*)GBlock)[thread * 32 + 4 * i + 0];
			DataChunk[0].hi = ((uint8*)GBlock)[thread * 32 + 4 * i + 1];
			DataChunk[1].lo = ((uint8*)GBlock)[thread * 32 + 4 * i + 2];
			DataChunk[1].hi = ((uint8*)GBlock)[thread * 32 + 4 * i + 3];
			uint2 DataTmp2[8];
			blake2b_compress4x((uint2*)&DataTmp2, (uint2*)&DataTmp, (uint2*)DataChunk, len, i == 7);
			for (int i = 0; i<8; i++)DataTmp[i] = DataTmp2[i];
			//              DataTmp = DataTmp2;
			//                              if(thread == 1) printf("%x %x\n",DataChunk[0].lo.s0, DataTmp[0].x);;

		}
#pragma unroll
		for (int i = 0; i<2; i++)
			a[thread * 2 + i] = DataTmp[i];




	}
}


/*
__host__ void mtp_i_cpu(int thr_id, uint32_t *block_header) {

	cudaSetDevice(device_map[thr_id]);
	cudaError_t err = cudaMemcpy(Header[thr_id], block_header, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice);
	if (err != cudaSuccess)
	{
		printf("%s\n", cudaGetErrorName(err));
		cudaDeviceReset();
		exit(1);
	}
	uint32_t tpb = 32;
	dim3 grid(4);
	dim3 block(tpb);

	mtp_i<0> << <grid, block >> >(HBlock[thr_id], Header[thr_id]);
	cudaDeviceSynchronize();
	mtp_i<1> << <grid, block >> >(HBlock[thr_id], Header[thr_id]);
	cudaDeviceSynchronize();
	mtp_i<2> << <grid, block >> >(HBlock[thr_id], Header[thr_id]);
	cudaDeviceSynchronize();
	mtp_i<3> << <grid, block >> >(HBlock[thr_id], Header[thr_id]);
	cudaDeviceSynchronize();

	tpb = 256;
	dim3 grid2(1048576 * 4 / tpb);
	dim3 block2(tpb);
	mtp_fc << <grid2, block2 >> >(1048576 * 4, HBlock[thr_id], buffer_a[thr_id]);
	cudaDeviceSynchronize();
}

__host__
void mtp_fill_1b(int thr_id, uint64_t *Block, uint32_t block_nr)
{
	uint4 *Blockptr = &HBlock[thr_id][block_nr * 64];
	cudaError_t err = cudaMemcpy(Blockptr, Block, 256 * sizeof(uint32_t), cudaMemcpyHostToDevice);
	if (err != cudaSuccess)
	{
		printf("%s\n", cudaGetErrorName(err));
		cudaDeviceReset();
		exit(1);
	}

}
*/