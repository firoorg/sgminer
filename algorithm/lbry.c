#include "config.h"
#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sph/sph_sha2.h"
#include "sph/sph_ripemd.h"


static inline void be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		dst[i] = htobe32(src[i]);
}

typedef struct {
  sph_sha256_context  sha256;
  sph_sha512_context  sha512;
  sph_ripemd160_context  ripemd;
} lbryhash_context_holder;

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
/*
void sha256_step1_host(uint32_t a, uint32_t b, uint32_t c, uint32_t &d, uint32_t e, uint32_t f, uint32_t g, uint32_t &h, uint32_t in, const uint32_t Kshared)
{
	uint32_t vxandx = (((f) ^ (g)) & (e)) ^ (g); // xandx(e, f, g);
	uint32_t bsg21 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25); // bsg2_1(e);
	uint32_t bsg20 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22); //bsg2_0(a);
	uint32_t andorv = ((b) & (c)) | (((b) | (c)) & (a)); //andor32(a,b,c);
	uint32_t t1 = h + bsg21 + vxandx + Kshared + in;
	uint32_t t2 = bsg20 + andorv;
	d = d + t1;
	h = t1 + t2;
}
*/
#define sha256_step1_host(a, b,  c, d,  e,  f,  g,  h,  in,  Kshared) \
{ \
	uint32_t vxandx = (((f) ^ (g)) & (e)) ^ (g);  \
	uint32_t bsg21 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25); \
	uint32_t bsg20 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22); \
	uint32_t andorv = ((b) & (c)) | (((b) | (c)) & (a)); \
	uint32_t t1 = h + bsg21 + vxandx + Kshared + in; \
	uint32_t t2 = bsg20 + andorv; \
	d = d + t1; \
	h = t1 + t2; \
}

/*
void sha256_step2_host(uint32_t a, uint32_t b, uint32_t c, uint32_t &d,
	uint32_t e, uint32_t f, uint32_t g, uint32_t &h, uint32_t* in, uint32_t pc, const uint32_t Kshared)
{
	int pcidx1 = (pc - 2) & 0xF;
	int pcidx2 = (pc - 7) & 0xF;
	int pcidx3 = (pc - 15) & 0xF;

	uint32_t inx0 = in[pc];
	uint32_t inx1 = in[pcidx1];
	uint32_t inx2 = in[pcidx2];
	uint32_t inx3 = in[pcidx3];

	uint32_t ssg21 = ROTR32(inx1, 17) ^ ROTR32(inx1, 19) ^ SPH_T32((inx1) >> 10); //ssg2_1(inx1);
	uint32_t ssg20 = ROTR32(inx3, 7) ^ ROTR32(inx3, 18) ^ SPH_T32((inx3) >> 3); //ssg2_0(inx3);
	uint32_t vxandx = (((f) ^ (g)) & (e)) ^ (g); // xandx(e, f, g);
	uint32_t bsg21 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25); // bsg2_1(e);
	uint32_t bsg20 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22); //bsg2_0(a);
	uint32_t andorv = ((b) & (c)) | (((b) | (c)) & (a)); //andor32(a,b,c);
	uint32_t t1, t2;

	in[pc] = ssg21 + inx2 + ssg20 + inx0;

	t1 = h + bsg21 + vxandx + Kshared + in[pc];
	t2 = bsg20 + andorv;
	d = d + t1;
	h = t1 + t2;
}

*/

#define sha256_step2_host(a, b, c, d, e, f,  g, h, in, pc, Kshared)  \
{  \
	int pcidx1 = (pc - 2) & 0xF; \
	int pcidx2 = (pc - 7) & 0xF; \
	int pcidx3 = (pc - 15) & 0xF; \
 \
	uint32_t inx0 = in[pc]; \
	uint32_t inx1 = in[pcidx1]; \
	uint32_t inx2 = in[pcidx2]; \
	uint32_t inx3 = in[pcidx3]; \
 \
	uint32_t ssg21 = ROTR32(inx1, 17) ^ ROTR32(inx1, 19) ^ SPH_T32((inx1) >> 10);  \
	uint32_t ssg20 = ROTR32(inx3, 7) ^ ROTR32(inx3, 18) ^ SPH_T32((inx3) >> 3);  \
	uint32_t vxandx = (((f) ^ (g)) & (e)) ^ (g);  \
	uint32_t bsg21 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);  \
	uint32_t bsg20 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);  \
	uint32_t andorv = ((b) & (c)) | (((b) | (c)) & (a)); \
	uint32_t t1, t2; \
 \
	in[pc] = ssg21 + inx2 + ssg20 + inx0; \
 \
	t1 = h + bsg21 + vxandx + Kshared + in[pc]; \
	t2 = bsg20 + andorv; \
	d = d + t1; \
	h = t1 + t2; \
}


void sha256_round_body_host(uint32_t* in, uint32_t* state, const uint32_t* Kshared)
{

	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t e = state[4];
	uint32_t f = state[5];
	uint32_t g = state[6];
	uint32_t h = state[7];

	sha256_step1_host(a, b, c, d, e, f, g, h, in[0], Kshared[0]);
	sha256_step1_host(h, a, b, c, d, e, f, g, in[1], Kshared[1]);
	sha256_step1_host(g, h, a, b, c, d, e, f, in[2], Kshared[2]);
	sha256_step1_host(f, g, h, a, b, c, d, e, in[3], Kshared[3]);
	sha256_step1_host(e, f, g, h, a, b, c, d, in[4], Kshared[4]);
	sha256_step1_host(d, e, f, g, h, a, b, c, in[5], Kshared[5]);
	sha256_step1_host(c, d, e, f, g, h, a, b, in[6], Kshared[6]);
	sha256_step1_host(b, c, d, e, f, g, h, a, in[7], Kshared[7]);
	sha256_step1_host(a, b, c, d, e, f, g, h, in[8], Kshared[8]);
	sha256_step1_host(h, a, b, c, d, e, f, g, in[9], Kshared[9]);
	sha256_step1_host(g, h, a, b, c, d, e, f, in[10], Kshared[10]);
	sha256_step1_host(f, g, h, a, b, c, d, e, in[11], Kshared[11]);
	sha256_step1_host(e, f, g, h, a, b, c, d, in[12], Kshared[12]);
	sha256_step1_host(d, e, f, g, h, a, b, c, in[13], Kshared[13]);
	sha256_step1_host(c, d, e, f, g, h, a, b, in[14], Kshared[14]);
	sha256_step1_host(b, c, d, e, f, g, h, a, in[15], Kshared[15]);

	for (int i = 0; i<3; i++)
	{
		sha256_step2_host(a, b, c, d, e, f, g, h, in, 0, Kshared[16 + 16 * i]);
		sha256_step2_host(h, a, b, c, d, e, f, g, in, 1, Kshared[17 + 16 * i]);
		sha256_step2_host(g, h, a, b, c, d, e, f, in, 2, Kshared[18 + 16 * i]);
		sha256_step2_host(f, g, h, a, b, c, d, e, in, 3, Kshared[19 + 16 * i]);
		sha256_step2_host(e, f, g, h, a, b, c, d, in, 4, Kshared[20 + 16 * i]);
		sha256_step2_host(d, e, f, g, h, a, b, c, in, 5, Kshared[21 + 16 * i]);
		sha256_step2_host(c, d, e, f, g, h, a, b, in, 6, Kshared[22 + 16 * i]);
		sha256_step2_host(b, c, d, e, f, g, h, a, in, 7, Kshared[23 + 16 * i]);
		sha256_step2_host(a, b, c, d, e, f, g, h, in, 8, Kshared[24 + 16 * i]);
		sha256_step2_host(h, a, b, c, d, e, f, g, in, 9, Kshared[25 + 16 * i]);
		sha256_step2_host(g, h, a, b, c, d, e, f, in, 10, Kshared[26 + 16 * i]);
		sha256_step2_host(f, g, h, a, b, c, d, e, in, 11, Kshared[27 + 16 * i]);
		sha256_step2_host(e, f, g, h, a, b, c, d, in, 12, Kshared[28 + 16 * i]);
		sha256_step2_host(d, e, f, g, h, a, b, c, in, 13, Kshared[29 + 16 * i]);
		sha256_step2_host(c, d, e, f, g, h, a, b, in, 14, Kshared[30 + 16 * i]);
		sha256_step2_host(b, c, d, e, f, g, h, a, in, 15, Kshared[31 + 16 * i]);
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}


void precalc_hash_sha256(dev_blk_ctx *blk, uint32_t *state, uint32_t *pdata)
{
	static const uint32_t cpu_H256[8] = {
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
	};
	static const uint32_t  cpu_K[64] = {
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};
	uint32_t in[16], buf[8], end[16];
	for (int i = 0; i<16; i++) in[i] = /*bswap_32*/(pdata[i]);
//	be32enc_vect(in, (const uint32_t *)pdata, 16);

	for (int i = 0; i<8; i++) buf[i] = cpu_H256[i];
	for (int i = 0; i<11; i++) end[i] = /*bswap_32*/(pdata[16 + i]);

	sha256_round_body_host(in, buf, cpu_K);
	
//	cudaMemcpyToSymbol(c_midstate112, buf, 32, 0, cudaMemcpyHostToDevice);
	blk->midstate.s0 = buf[0];
	blk->midstate.s1 = buf[1];
	blk->midstate.s2 = buf[2];
	blk->midstate.s3 = buf[3];
	blk->midstate.s4 = buf[4];
	blk->midstate.s5 = buf[5];
	blk->midstate.s6 = buf[6];
	blk->midstate.s7 = buf[7];

	uint32_t a = buf[0];
	uint32_t b = buf[1];
	uint32_t c = buf[2];
	uint32_t d = buf[3];
	uint32_t e = buf[4];
	uint32_t f = buf[5];
	uint32_t g = buf[6];
	uint32_t h = buf[7];

	sha256_step1_host(a, b, c, d, e, f, g, h, end[0], cpu_K[0]);
	sha256_step1_host(h, a, b, c, d, e, f, g, end[1], cpu_K[1]);
	sha256_step1_host(g, h, a, b, c, d, e, f, end[2], cpu_K[2]);
	sha256_step1_host(f, g, h, a, b, c, d, e, end[3], cpu_K[3]);
	sha256_step1_host(e, f, g, h, a, b, c, d, end[4], cpu_K[4]);
	sha256_step1_host(d, e, f, g, h, a, b, c, end[5], cpu_K[5]);
	sha256_step1_host(c, d, e, f, g, h, a, b, end[6], cpu_K[6]);
	sha256_step1_host(b, c, d, e, f, g, h, a, end[7], cpu_K[7]);
	sha256_step1_host(a, b, c, d, e, f, g, h, end[8], cpu_K[8]);
	sha256_step1_host(h, a, b, c, d, e, f, g, end[9], cpu_K[9]);
	sha256_step1_host(g, h, a, b, c, d, e, f, end[10], cpu_K[10]);
	sha256_step1_host(f, g, h, a, b, c, d, e, 0, cpu_K[11]);

	buf[0] = a;
	buf[1] = b;
	buf[2] = c;
	buf[3] = d;
	buf[4] = e;
	buf[5] = f;
	buf[6] = g;
	buf[7] = h;

//	cudaMemcpyToSymbol(c_midbuffer112, buf, 32, 0, cudaMemcpyHostToDevice);
	blk->midbuffer.s0 = buf[0];
	blk->midbuffer.s1 = buf[1];
	blk->midbuffer.s2 = buf[2];
	blk->midbuffer.s3 = buf[3];
	blk->midbuffer.s4 = buf[4];
	blk->midbuffer.s5 = buf[5];
	blk->midbuffer.s6 = buf[6];
	blk->midbuffer.s7 = buf[7];
	end[12] = 0x80000000;
	end[13] = 0;
	end[14] = 0;
	end[15] = 0x380;
	uint32_t x2_0, x2_1;

	x2_0 = ROTR32(end[1], 7) ^ ROTR32(end[1], 18) ^ (end[1] >> 3); //ssg2_0(inx3);//ssg2_0(end[1]);
	//	x2_1 = ROTR32(end[14], 17) ^ ROTR32(end[14], 19) ^ SPH_T32(end[14] >> 10) + x2_0; //ssg2_1(inx1); ssg2_1(end[14]) + x2_0;
	end[0] = end[0] + end[9] + x2_0;

	x2_0 = ROTR32(end[2], 7) ^ ROTR32(end[2], 18) ^ (end[2] >> 3);
	x2_1 = (ROTR32(end[15], 17) ^ ROTR32(end[15], 19) ^ (end[15] >> 10)) + x2_0;
	end[1] = end[1] + end[10] + x2_1;

	x2_0 = ROTR32(end[3], 7) ^ ROTR32(end[3], 18) ^ (end[3] >> 3);//ssg2_0(end[3]);
	x2_1 = (ROTR32(end[0], 17) ^ ROTR32(end[0], 19) ^ (end[0] >> 10)) + x2_0;
	end[2] += x2_1;

	x2_0 = ROTR32(end[4], 7) ^ ROTR32(end[4], 18) ^ (end[4] >> 3);//ssg2_0(end[4]);
	x2_1 = (ROTR32(end[1], 17) ^ ROTR32(end[1], 19) ^ (end[1] >> 10)) + x2_0;
	end[3] = end[3] + end[12] + x2_1;

	x2_0 = ROTR32(end[5], 7) ^ ROTR32(end[5], 18) ^ (end[5] >> 3);//ssg2_0(end[4]);
	end[4] = end[4] + end[13] + x2_0;

	x2_0 = ROTR32(end[6], 7) ^ ROTR32(end[6], 18) ^ (end[6] >> 3);//ssg2_0(end[6]);
	x2_1 = (ROTR32(end[3], 17) ^ ROTR32(end[3], 19) ^ (end[3] >> 10)) + x2_0;
	end[5] = end[5] + end[14] + x2_1;

	x2_0 = ROTR32(end[7], 7) ^ ROTR32(end[7], 18) ^ (end[7] >> 3);//ssg2_0(end[7]);
	end[6] = end[6] + end[15] + x2_0;

	x2_0 = ROTR32(end[8], 7) ^ ROTR32(end[8], 18) ^ (end[8] >> 3);//ssg2_0(end[8]);
	x2_1 = (ROTR32(end[5], 17) ^ ROTR32(end[5], 19) ^ (end[5] >> 10)) + x2_0;
	end[7] = end[7] + end[0] + x2_1;

	x2_0 = ROTR32(end[9], 7) ^ ROTR32(end[9], 18) ^ (end[9] >> 3);//ssg2_0(end[9]);
	end[8] = end[8] + end[1] + x2_0;

	x2_0 = ROTR32(end[10], 7) ^ ROTR32(end[10], 18) ^ (end[10] >> 3);//ssg2_0(end[10]);
	x2_1 = (ROTR32(end[7], 17) ^ ROTR32(end[7], 19) ^ (end[7] >> 10)) + x2_0;
	end[9] = end[9] + x2_1;

//	cudaMemcpyToSymbol(c_dataEnd112, end, sizeof(end), 0, cudaMemcpyHostToDevice);
	blk->dataend.s0 = end[0];
	blk->dataend.s1 = end[1];
	blk->dataend.s2 = end[2];
	blk->dataend.s3 = end[3];
	blk->dataend.s4 = end[4];
	blk->dataend.s5 = end[5];
	blk->dataend.s6 = end[6];
	blk->dataend.s7 = end[7];
	blk->dataend.s8 = end[8];
	blk->dataend.s9 = end[9];
	blk->dataend.sa = end[10];
	blk->dataend.sb = end[11];
}


void precalc_hash_sha256_test(dev_blk_ctx *blk, uint32_t *state, uint32_t *pdata)
{
	
	uint32_t data[16];
	sph_sha256_context  sha256;
	be32enc_vect(data, (const uint32_t *)pdata, 16);

	sph_sha256_init(&sha256);
	sph_sha256(&sha256, pdata, 64);

	blk->midstate.s0 = ((uint32_t*)sha256.buf)[0];
	blk->midstate.s1 = ((uint32_t*)sha256.buf)[1];
	blk->midstate.s2 = ((uint32_t*)sha256.buf)[2];
	blk->midstate.s3 = ((uint32_t*)sha256.buf)[3];
	blk->midstate.s4 = ((uint32_t*)sha256.buf)[4];
	blk->midstate.s5 = ((uint32_t*)sha256.buf)[5];
	blk->midstate.s6 = ((uint32_t*)sha256.buf)[6];
	blk->midstate.s7 = ((uint32_t*)sha256.buf)[7];
}

void lbryhash(void* output, const void* input)
{
  uint32_t hashA[16], hashB[16], hashC[16];
  lbryhash_context_holder ctx;

  sph_sha256_init(&ctx.sha256);
  sph_sha512_init(&ctx.sha512);
  sph_ripemd160_init(&ctx.ripemd);

  sph_sha256 (&ctx.sha256, input, 112);
  sph_sha256_close(&ctx.sha256, hashA);

  sph_sha256 (&ctx.sha256, hashA, 32);
  sph_sha256_close(&ctx.sha256, hashA);

  sph_sha512 (&ctx.sha512, hashA, 32);
  sph_sha512_close(&ctx.sha512, hashA);

  sph_ripemd160 (&ctx.ripemd, hashA, 32);
  sph_ripemd160_close(&ctx.ripemd, hashB);

  sph_ripemd160 (&ctx.ripemd, hashA+8, 32);
  sph_ripemd160_close(&ctx.ripemd, hashC);

  sph_sha256 (&ctx.sha256, hashB, 20);
  sph_sha256 (&ctx.sha256, hashC, 20);
  sph_sha256_close(&ctx.sha256, hashA);

  sph_sha256 (&ctx.sha256, hashA, 32);
  sph_sha256_close(&ctx.sha256, hashA);

  memcpy(output, hashA, 32);
}

void lbry_regenhash(struct work *work)
{
  uint32_t data[28];
  uint32_t *nonce = (uint32_t *)(work->data + 108);
  uint32_t *ohash = (uint32_t *)(work->hash);

  be32enc_vect(data, (const uint32_t *)work->data, 27);
  data[27] = htobe32(*nonce);
  lbryhash(ohash, data);
}

#undef sha256_step2_host
#undef sha256_step1_host