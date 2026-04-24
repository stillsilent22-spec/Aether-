/*
 * ed25519_ref10.h -- Header-only Ed25519 keypair generation, C89.
 *
 * Based on the public domain SUPERCOP ref10 by
 *   D.J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, Bo-Yin Yang.
 * SHA-512 per FIPS PUB 180-4 (public domain).
 *
 * Public API (the only symbol exported):
 *   void ed25519_ref10_keypair(
 *       unsigned char *pk,          -- 32 bytes output
 *       unsigned char *sk,          -- 64 bytes output (= seed || pk)
 *       const unsigned char *seed   -- 32 bytes input  (from CSPRNG)
 *   );
 *
 * All internals are static.
 * Safe to include from a single translation unit only.
 */

#ifndef ED25519_REF10_H
#define ED25519_REF10_H

#include <string.h>

/* ── Portable integer types (C89) ───────────────────────────────────────── */

#ifdef _MSC_VER
  typedef unsigned __int8  r10u8;
  typedef   signed __int32 r10s32;
  typedef unsigned __int32 r10u32;
  typedef   signed __int64 r10s64;
  typedef unsigned __int64 r10u64;
#else
  typedef unsigned char        r10u8;
  typedef int                  r10s32;
  typedef unsigned int         r10u32;
  typedef long long            r10s64;
  typedef unsigned long long   r10u64;
#endif

/* ── SHA-512 (FIPS PUB 180-4) ────────────────────────────────────────────── */

#define R512_ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define R512_CH(e,f,g) (((e)&(f))^(~(e)&(g)))
#define R512_MAJ(a,b,c)(((a)&(b))^((a)&(c))^((b)&(c)))
#define R512_S0(a) (R512_ROTR(a,28)^R512_ROTR(a,34)^R512_ROTR(a,39))
#define R512_S1(e) (R512_ROTR(e,14)^R512_ROTR(e,18)^R512_ROTR(e,41))
#define R512_s0(w) (R512_ROTR(w, 1)^R512_ROTR(w, 8)^((w)>> 7))
#define R512_s1(w) (R512_ROTR(w,19)^R512_ROTR(w,61)^((w)>> 6))

static const r10u64 sha512_K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

typedef struct { r10u64 st[8]; r10u64 bc[2]; r10u8 buf[128]; r10u32 bl; } sha512_ctx;

static void sha512_compress(sha512_ctx *c, const r10u8 *blk)
{
    r10u64 w[80], a, b, cv, d, e, fv, g, h, t1, t2;
    int i;
    for (i=0; i<16; i++) {
        int j=i*8;
        w[i]=((r10u64)blk[j]<<56)|((r10u64)blk[j+1]<<48)
            |((r10u64)blk[j+2]<<40)|((r10u64)blk[j+3]<<32)
            |((r10u64)blk[j+4]<<24)|((r10u64)blk[j+5]<<16)
            |((r10u64)blk[j+6]<<8) |((r10u64)blk[j+7]);
    }
    for (i=16; i<80; i++) w[i]=R512_s1(w[i-2])+w[i-7]+R512_s0(w[i-15])+w[i-16];
    a=c->st[0]; b=c->st[1]; cv=c->st[2]; d=c->st[3];
    e=c->st[4]; fv=c->st[5]; g=c->st[6]; h=c->st[7];
    for (i=0; i<80; i++) {
        t1=h+R512_S1(e)+R512_CH(e,fv,g)+sha512_K[i]+w[i];
        t2=R512_S0(a)+R512_MAJ(a,b,cv);
        h=g; g=fv; fv=e; e=d+t1; d=cv; cv=b; b=a; a=t1+t2;
    }
    c->st[0]+=a; c->st[1]+=b; c->st[2]+=cv; c->st[3]+=d;
    c->st[4]+=e; c->st[5]+=fv; c->st[6]+=g; c->st[7]+=h;
}

static void sha512_init(sha512_ctx *c)
{
    c->st[0]=0x6a09e667f3bcc908ULL; c->st[1]=0xbb67ae8584caa73bULL;
    c->st[2]=0x3c6ef372fe94f82bULL; c->st[3]=0xa54ff53a5f1d36f1ULL;
    c->st[4]=0x510e527fade682d1ULL; c->st[5]=0x9b05688c2b3e6c1fULL;
    c->st[6]=0x1f83d9abfb41bd6bULL; c->st[7]=0x5be0cd19137e2179ULL;
    c->bc[0]=c->bc[1]=0; c->bl=0;
}

static void sha512_update(sha512_ctx *c, const r10u8 *in, r10u32 len)
{
    r10u32 left=(r10u32)(128 - c->bl);
    r10u64 lo, hi;
    lo=c->bc[0]+((r10u64)len<<3); hi=c->bc[1]+((r10u64)len>>61);
    if (lo<c->bc[0]) hi++;
    c->bc[0]=lo; c->bc[1]=hi;
    if (len>=left) {
        memcpy(c->buf+c->bl, in, left);
        sha512_compress(c, c->buf);
        in+=left; len-=left; c->bl=0;
        while (len>=128) { sha512_compress(c,in); in+=128; len-=128; }
    }
    memcpy(c->buf+c->bl, in, len); c->bl+=len;
}

static void sha512_final(sha512_ctx *c, r10u8 out[64])
{
    r10u8 pad[128];
    r10u32 pl;
    int i;
    memset(pad,0,128); pad[0]=0x80;
    pl=(c->bl<112)?(112-c->bl):(240-c->bl);
    sha512_update(c, pad, pl);
    pad[0]=(r10u8)(c->bc[1]>>56); pad[1]=(r10u8)(c->bc[1]>>48);
    pad[2]=(r10u8)(c->bc[1]>>40); pad[3]=(r10u8)(c->bc[1]>>32);
    pad[4]=(r10u8)(c->bc[1]>>24); pad[5]=(r10u8)(c->bc[1]>>16);
    pad[6]=(r10u8)(c->bc[1]>> 8); pad[7]=(r10u8)(c->bc[1]    );
    pad[8]=(r10u8)(c->bc[0]>>56); pad[9]=(r10u8)(c->bc[0]>>48);
    pad[10]=(r10u8)(c->bc[0]>>40); pad[11]=(r10u8)(c->bc[0]>>32);
    pad[12]=(r10u8)(c->bc[0]>>24); pad[13]=(r10u8)(c->bc[0]>>16);
    pad[14]=(r10u8)(c->bc[0]>> 8); pad[15]=(r10u8)(c->bc[0]    );
    sha512_update(c, pad, 16);
    for (i=0; i<8; i++) {
        out[i*8+0]=(r10u8)(c->st[i]>>56); out[i*8+1]=(r10u8)(c->st[i]>>48);
        out[i*8+2]=(r10u8)(c->st[i]>>40); out[i*8+3]=(r10u8)(c->st[i]>>32);
        out[i*8+4]=(r10u8)(c->st[i]>>24); out[i*8+5]=(r10u8)(c->st[i]>>16);
        out[i*8+6]=(r10u8)(c->st[i]>> 8); out[i*8+7]=(r10u8)(c->st[i]    );
    }
}

static void sha512_hash(r10u8 out[64], const r10u8 *in, r10u32 len)
{
    sha512_ctx c;
    sha512_init(&c);
    sha512_update(&c,in,len);
    sha512_final(&c,out);
}

/* ── GF(2^255-19) field elements (ref10 radix 2^25.5) ───────────────────── */

typedef r10s32 fe[10];

static void fe_0   (fe h){int i;for(i=0;i<10;i++)h[i]=0;}
static void fe_1   (fe h){fe_0(h);h[0]=1;}
static void fe_copy(fe h,const fe f){int i;for(i=0;i<10;i++)h[i]=f[i];}
static void fe_add (fe h,const fe f,const fe g){int i;for(i=0;i<10;i++)h[i]=f[i]+g[i];}
static void fe_sub (fe h,const fe f,const fe g){int i;for(i=0;i<10;i++)h[i]=f[i]-g[i];}
static void fe_neg (fe h,const fe f){int i;for(i=0;i<10;i++)h[i]=-f[i];}

static void fe_tobytes(r10u8 *s, const fe h)
{
    r10s32 h0=h[0],h1=h[1],h2=h[2],h3=h[3],h4=h[4];
    r10s32 h5=h[5],h6=h[6],h7=h[7],h8=h[8],h9=h[9];
    r10s32 q,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9;
    q=(19*h9+((r10s32)1<<24))>>25;q=(h0+q)>>26;q=(h1+q)>>25;q=(h2+q)>>26;
    q=(h3+q)>>25;q=(h4+q)>>26;q=(h5+q)>>25;q=(h6+q)>>26;q=(h7+q)>>25;
    q=(h8+q)>>26;q=(h9+q)>>25;
    h0+=19*q;
    c0=h0>>26;h1+=c0;h0-=c0<<26; c1=h1>>25;h2+=c1;h1-=c1<<25;
    c2=h2>>26;h3+=c2;h2-=c2<<26; c3=h3>>25;h4+=c3;h3-=c3<<25;
    c4=h4>>26;h5+=c4;h4-=c4<<26; c5=h5>>25;h6+=c5;h5-=c5<<25;
    c6=h6>>26;h7+=c6;h6-=c6<<26; c7=h7>>25;h8+=c7;h7-=c7<<25;
    c8=h8>>26;h9+=c8;h8-=c8<<26; c9=h9>>25;h9-=c9<<25;
    s[ 0]=(r10u8)(h0      );s[ 1]=(r10u8)(h0>> 8);s[ 2]=(r10u8)(h0>>16);
    s[ 3]=(r10u8)((h0>>24)|(h1<<2));s[ 4]=(r10u8)(h1>> 6);s[ 5]=(r10u8)(h1>>14);
    s[ 6]=(r10u8)((h1>>22)|(h2<<3));s[ 7]=(r10u8)(h2>> 5);s[ 8]=(r10u8)(h2>>13);
    s[ 9]=(r10u8)((h2>>21)|(h3<<5));s[10]=(r10u8)(h3>> 3);s[11]=(r10u8)(h3>>11);
    s[12]=(r10u8)((h3>>19)|(h4<<6));s[13]=(r10u8)(h4>> 2);s[14]=(r10u8)(h4>>10);
    s[15]=(r10u8)(h4>>18);
    s[16]=(r10u8)(h5      );s[17]=(r10u8)(h5>> 8);s[18]=(r10u8)(h5>>16);
    s[19]=(r10u8)((h5>>24)|(h6<<1));s[20]=(r10u8)(h6>> 7);s[21]=(r10u8)(h6>>15);
    s[22]=(r10u8)((h6>>23)|(h7<<3));s[23]=(r10u8)(h7>> 5);s[24]=(r10u8)(h7>>13);
    s[25]=(r10u8)((h7>>21)|(h8<<4));s[26]=(r10u8)(h8>> 4);s[27]=(r10u8)(h8>>12);
    s[28]=(r10u8)((h8>>20)|(h9<<6));s[29]=(r10u8)(h9>> 2);s[30]=(r10u8)(h9>>10);
    s[31]=(r10u8)(h9>>18);
    (void)c0;(void)c1;(void)c2;(void)c3;(void)c4;
    (void)c5;(void)c6;(void)c7;(void)c8;(void)c9;
}

/* Returns 1 if h is negative (odd), 0 if non-negative */
static int fe_isnegative(const fe h)
{
    r10u8 s[32];
    fe_tobytes(s,h);
    return s[0]&1;
}

static void fe_frombytes(fe h, const r10u8 *s)
{
    r10s64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9;
    r10s64 c0,c1,c2,c3,c4,c5,c6,c7,c8,c9;
    h0=((r10u32)s[0]|((r10u32)s[1]<<8)|((r10u32)s[2]<<16)|((r10u32)s[3]<<24))&0x3ffffffL;
    h1=(((r10u32)s[3]|((r10u32)s[4]<<8)|((r10u32)s[5]<<16)|((r10u32)s[6]<<24))>>2)&0x1ffffffL;
    h2=(((r10u32)s[6]|((r10u32)s[7]<<8)|((r10u32)s[8]<<16)|((r10u32)s[9]<<24))>>5)&0x3ffffffL;
    h3=(((r10u32)s[9]|((r10u32)s[10]<<8)|((r10u32)s[11]<<16)|((r10u32)s[12]<<24))>>3)&0x1ffffffL;
    h4=(((r10u32)s[12]|((r10u32)s[13]<<8)|((r10u32)s[14]<<16)|((r10u32)s[15]<<24))>>6)&0x3ffffffL;
    h5=((r10u32)s[16]|((r10u32)s[17]<<8)|((r10u32)s[18]<<16)|((r10u32)s[19]<<24))&0x1ffffffL;
    h6=(((r10u32)s[19]|((r10u32)s[20]<<8)|((r10u32)s[21]<<16)|((r10u32)s[22]<<24))>>1)&0x3ffffffL;
    h7=(((r10u32)s[22]|((r10u32)s[23]<<8)|((r10u32)s[24]<<16)|((r10u32)s[25]<<24))>>3)&0x1ffffffL;
    h8=(((r10u32)s[25]|((r10u32)s[26]<<8)|((r10u32)s[27]<<16)|((r10u32)s[28]<<24))>>4)&0x3ffffffL;
    h9=(((r10u32)s[28]|((r10u32)s[29]<<8)|((r10u32)s[30]<<16)|((r10u32)s[31]<<24))>>6)&0x1ffffffL;
    c9=(h9+(r10s64)(1<<24))>>25;h0+=c9*19;h9-=c9<<25;
    c1=(h1+(r10s64)(1<<24))>>25;h2+=c1;h1-=c1<<25;
    c3=(h3+(r10s64)(1<<24))>>25;h4+=c3;h3-=c3<<25;
    c5=(h5+(r10s64)(1<<24))>>25;h6+=c5;h5-=c5<<25;
    c7=(h7+(r10s64)(1<<24))>>25;h8+=c7;h7-=c7<<25;
    c0=(h0+(r10s64)(1<<25))>>26;h1+=c0;h0-=c0<<26;
    c2=(h2+(r10s64)(1<<25))>>26;h3+=c2;h2-=c2<<26;
    c4=(h4+(r10s64)(1<<25))>>26;h5+=c4;h4-=c4<<26;
    c6=(h6+(r10s64)(1<<25))>>26;h7+=c6;h6-=c6<<26;
    c8=(h8+(r10s64)(1<<25))>>26;h9+=c8;h8-=c8<<26;
    h[0]=(r10s32)h0;h[1]=(r10s32)h1;h[2]=(r10s32)h2;h[3]=(r10s32)h3;h[4]=(r10s32)h4;
    h[5]=(r10s32)h5;h[6]=(r10s32)h6;h[7]=(r10s32)h7;h[8]=(r10s32)h8;h[9]=(r10s32)h9;
}

static void fe_mul(fe h, const fe f, const fe g)
{
    r10s64 f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    r10s64 f5=f[5],f6=f[6],f7=f[7],f8=f[8],f9=f[9];
    r10s64 g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4];
    r10s64 g5=g[5],g6=g[6],g7=g[7],g8=g[8],g9=g[9];
    r10s64 g1x=19*g1,g2x=19*g2,g3x=19*g3,g4x=19*g4;
    r10s64 g5x=19*g5,g6x=19*g6,g7x=19*g7,g8x=19*g8,g9x=19*g9;
    r10s64 f1_2=2*f1,f3_2=2*f3,f5_2=2*f5,f7_2=2*f7,f9_2=2*f9;
    r10s64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9;
    r10s64 c0,c1,c2,c3,c4,c5,c6,c7,c8,c9;
    h0=f0*g0+f1_2*g9x+f2*g8x+f3_2*g7x+f4*g6x+f5_2*g5x+f6*g4x+f7_2*g3x+f8*g2x+f9_2*g1x;
    h1=f0*g1+f1*g0+f2*g9x+f3*g8x+f4*g7x+f5*g6x+f6*g5x+f7*g4x+f8*g3x+f9*g2x;
    h2=f0*g2+f1_2*g1+f2*g0+f3_2*g9x+f4*g8x+f5_2*g7x+f6*g6x+f7_2*g5x+f8*g4x+f9_2*g3x;
    h3=f0*g3+f1*g2+f2*g1+f3*g0+f4*g9x+f5*g8x+f6*g7x+f7*g6x+f8*g5x+f9*g4x;
    h4=f0*g4+f1_2*g3+f2*g2+f3_2*g1+f4*g0+f5_2*g9x+f6*g8x+f7_2*g7x+f8*g6x+f9_2*g5x;
    h5=f0*g5+f1*g4+f2*g3+f3*g2+f4*g1+f5*g0+f6*g9x+f7*g8x+f8*g7x+f9*g6x;
    h6=f0*g6+f1_2*g5+f2*g4+f3_2*g3+f4*g2+f5_2*g1+f6*g0+f7_2*g9x+f8*g8x+f9_2*g7x;
    h7=f0*g7+f1*g6+f2*g5+f3*g4+f4*g3+f5*g2+f6*g1+f7*g0+f8*g9x+f9*g8x;
    h8=f0*g8+f1_2*g7+f2*g6+f3_2*g5+f4*g4+f5_2*g3+f6*g2+f7_2*g1+f8*g0+f9_2*g9x;
    h9=f0*g9+f1*g8+f2*g7+f3*g6+f4*g5+f5*g4+f6*g3+f7*g2+f8*g1+f9*g0;
    c0=(h0+(r10s64)(1<<25))>>26;h1+=c0;h0-=c0<<26;
    c4=(h4+(r10s64)(1<<25))>>26;h5+=c4;h4-=c4<<26;
    c1=(h1+(r10s64)(1<<24))>>25;h2+=c1;h1-=c1<<25;
    c5=(h5+(r10s64)(1<<24))>>25;h6+=c5;h5-=c5<<25;
    c2=(h2+(r10s64)(1<<25))>>26;h3+=c2;h2-=c2<<26;
    c6=(h6+(r10s64)(1<<25))>>26;h7+=c6;h6-=c6<<26;
    c3=(h3+(r10s64)(1<<24))>>25;h4+=c3;h3-=c3<<25;
    c7=(h7+(r10s64)(1<<24))>>25;h8+=c7;h7-=c7<<25;
    c4=(h4+(r10s64)(1<<25))>>26;h5+=c4;h4-=c4<<26;
    c8=(h8+(r10s64)(1<<25))>>26;h9+=c8;h8-=c8<<26;
    c9=(h9+(r10s64)(1<<24))>>25;h0+=c9*19;h9-=c9<<25;
    c0=(h0+(r10s64)(1<<25))>>26;h1+=c0;h0-=c0<<26;
    h[0]=(r10s32)h0;h[1]=(r10s32)h1;h[2]=(r10s32)h2;h[3]=(r10s32)h3;h[4]=(r10s32)h4;
    h[5]=(r10s32)h5;h[6]=(r10s32)h6;h[7]=(r10s32)h7;h[8]=(r10s32)h8;h[9]=(r10s32)h9;
}

static void fe_sq(fe h, const fe f)
{
    r10s64 f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    r10s64 f5=f[5],f6=f[6],f7=f[7],f8=f[8],f9=f[9];
    r10s64 f0_2=2*f0,f1_2=2*f1,f2_2=2*f2,f3_2=2*f3,f4_2=2*f4;
    r10s64 f5_2=2*f5,f6_2=2*f6,f7_2=2*f7;
    r10s64 f5_38=38*f5,f6_19=19*f6,f7_38=38*f7,f8_19=19*f8,f9_38=38*f9;
    r10s64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9;
    r10s64 c0,c1,c2,c3,c4,c5,c6,c7,c8,c9;
    h0=f0*f0+f1_2*f9_38+f2_2*f8_19+f3_2*f7_38+f4_2*f6_19+f5*f5_38;
    h1=f0_2*f1+f2*f9_38+f3_2*f8_19+f4*f7_38+f5_2*f6_19;
    h2=f0_2*f2+f1_2*f1+f3_2*f9_38+f4_2*f8_19+f5_2*f7_38+f6*f6_19;
    h3=f0_2*f3+f1_2*f2+f4*f9_38+f5_2*f8_19+f6*f7_38;
    h4=f0_2*f4+f1_2*f3_2+f2*f2+f5_2*f9_38+f6_2*f8_19+f7*f7_38;
    h5=f0_2*f5+f1_2*f4+f2_2*f3+f6*f9_38+f7_2*f8_19;
    h6=f0_2*f6+f1_2*f5_2+f2_2*f4+f3_2*f3+f7_2*f9_38+f8*f8_19;
    h7=f0_2*f7+f1_2*f6+f2_2*f5+f3_2*f4+f8*f9_38;
    h8=f0_2*f8+f1_2*f7_2+f2_2*f6+f3_2*f5_2+f4*f4+f9*f9_38;
    h9=f0_2*f9+f1_2*f8+f2_2*f7+f3_2*f6+f4_2*f5;
    c0=(h0+(r10s64)(1<<25))>>26;h1+=c0;h0-=c0<<26;
    c4=(h4+(r10s64)(1<<25))>>26;h5+=c4;h4-=c4<<26;
    c1=(h1+(r10s64)(1<<24))>>25;h2+=c1;h1-=c1<<25;
    c5=(h5+(r10s64)(1<<24))>>25;h6+=c5;h5-=c5<<25;
    c2=(h2+(r10s64)(1<<25))>>26;h3+=c2;h2-=c2<<26;
    c6=(h6+(r10s64)(1<<25))>>26;h7+=c6;h6-=c6<<26;
    c3=(h3+(r10s64)(1<<24))>>25;h4+=c3;h3-=c3<<25;
    c7=(h7+(r10s64)(1<<24))>>25;h8+=c7;h7-=c7<<25;
    c4=(h4+(r10s64)(1<<25))>>26;h5+=c4;h4-=c4<<26;
    c8=(h8+(r10s64)(1<<25))>>26;h9+=c8;h8-=c8<<26;
    c9=(h9+(r10s64)(1<<24))>>25;h0+=c9*19;h9-=c9<<25;
    c0=(h0+(r10s64)(1<<25))>>26;h1+=c0;h0-=c0<<26;
    h[0]=(r10s32)h0;h[1]=(r10s32)h1;h[2]=(r10s32)h2;h[3]=(r10s32)h3;h[4]=(r10s32)h4;
    h[5]=(r10s32)h5;h[6]=(r10s32)h6;h[7]=(r10s32)h7;h[8]=(r10s32)h8;h[9]=(r10s32)h9;
}

static void fe_invert(fe out, const fe z)
{
    fe t0,t1,t2,t3;
    int i;
    fe_sq(t0,z); fe_sq(t1,t0);fe_sq(t1,t1);fe_mul(t1,z,t1);fe_mul(t0,t0,t1);
    fe_sq(t2,t0);fe_mul(t1,t1,t2);
    fe_sq(t2,t1);for(i=1;i<5;i++)fe_sq(t2,t2);fe_mul(t1,t2,t1);
    fe_sq(t2,t1);for(i=1;i<10;i++)fe_sq(t2,t2);fe_mul(t2,t2,t1);
    fe_sq(t3,t2);for(i=1;i<20;i++)fe_sq(t3,t3);fe_mul(t2,t3,t2);
    fe_sq(t2,t2);for(i=1;i<10;i++)fe_sq(t2,t2);fe_mul(t1,t2,t1);
    fe_sq(t2,t1);for(i=1;i<50;i++)fe_sq(t2,t2);fe_mul(t2,t2,t1);
    fe_sq(t3,t2);for(i=1;i<100;i++)fe_sq(t3,t3);fe_mul(t2,t3,t2);
    fe_sq(t2,t2);for(i=1;i<50;i++)fe_sq(t2,t2);fe_mul(t1,t2,t1);
    fe_sq(t1,t1);for(i=1;i<5;i++)fe_sq(t1,t1);fe_mul(out,t1,t0);
}

/* ── Extended twisted Edwards group element ──────────────────────────────── */

typedef struct { fe X; fe Y; fe Z; fe T; } ge_p3;

static void ge_p3_tobytes(r10u8 *s, const ge_p3 *h)
{
    fe recip,x,y;
    fe_invert(recip,h->Z);
    fe_mul(x,h->X,recip);
    fe_mul(y,h->Y,recip);
    fe_tobytes(s,y);
    s[31]^=(r10u8)(fe_isnegative(x)<<7);
}

/* Complete doubling formula for twisted Edwards curve with a=-1 */
static void ge_p3_dbl(ge_p3 *r, const ge_p3 *p)
{
    fe A,B,C,D,E,F,G,H;
    fe_sq(A,p->X); fe_sq(B,p->Y); fe_sq(C,p->Z); fe_add(C,C,C);
    fe_neg(D,A);
    fe_add(E,p->X,p->Y); fe_sq(E,E); fe_sub(E,E,A); fe_sub(E,E,B);
    fe_add(G,D,B); fe_sub(F,G,C); fe_sub(H,D,B);
    fe_mul(r->X,E,F); fe_mul(r->Y,G,H); fe_mul(r->Z,F,G); fe_mul(r->T,E,H);
}

/*
 * Mixed addition: P3 += affine point given as (yplusx, yminusx, xy2d).
 * d2 = 2 * (-121665/121666 mod p), precomputed constant for Ed25519.
 */
static void ge_madd(ge_p3 *r, const ge_p3 *p,
                    const fe yplusx, const fe yminusx, const fe xy2d)
{
    fe A,B,C,D,E,F,G,H;
    fe_sub(A,p->Y,p->X); fe_mul(A,A,yminusx);
    fe_add(B,p->Y,p->X); fe_mul(B,B,yplusx);
    fe_mul(C,p->T,xy2d);
    fe_add(D,p->Z,p->Z);
    fe_sub(E,B,A); fe_sub(F,D,C); fe_add(G,D,C); fe_add(H,B,A);
    fe_mul(r->X,E,F); fe_mul(r->Y,G,H); fe_mul(r->Z,F,G); fe_mul(r->T,E,H);
}

/* ── Base point constants (Ed25519, little-endian) ───────────────────────── */

/*
 * Bx = 151122213495358... (standard Ed25519 base point x-coordinate)
 * By = 463168356949264... (y = 4/5 mod p)
 */
static const r10u8 r10_Bx[32] = {
    0x1a,0xd5,0x25,0x8f,0x60,0x2d,0x56,0xc9,
    0xb2,0xa7,0x25,0x95,0x60,0xc7,0x2c,0x69,
    0x5c,0xdc,0xd6,0xfd,0x31,0xe2,0xa4,0xc0,
    0xfe,0x53,0x6e,0xcd,0xd3,0x36,0x69,0x21
};
static const r10u8 r10_By[32] = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
};

/* 2*d = 2*(-121665/121666 mod p) in ref10 limb representation */
static const fe r10_d2 = {
    -21827239,-5839606,-30745221,13898782,229458,
    15978800,-12551817,-6495438,29715968,9444199
};

/* Scalar multiplication: h = a * BasePoint, a is a 255-bit scalar */
static void ge_scalarmult_base(ge_p3 *h, const r10u8 *a)
{
    ge_p3 B, acc;
    fe ypx, ymx, xy2d;

    /* Load base point in extended coordinates */
    fe_frombytes(B.X, r10_Bx);
    fe_frombytes(B.Y, r10_By);
    fe_1(B.Z);
    fe_mul(B.T, B.X, B.Y);

    /* Precompute the three values used by ge_madd */
    fe_add(ypx, B.Y, B.X);
    fe_sub(ymx, B.Y, B.X);
    fe_mul(xy2d, B.T, r10_d2);

    /* Start with neutral (0:1:1:0) */
    fe_0(acc.X); fe_1(acc.Y); fe_1(acc.Z); fe_0(acc.T);

    /* Standard double-and-add, bit 254 down to 0 */
    {
        int i;
        for (i=254; i>=0; i--) {
            int bit=(a[i>>3]>>(i&7))&1;
            ge_p3_dbl(&acc,&acc);
            if (bit) ge_madd(&acc,&acc,ypx,ymx,xy2d);
        }
    }

    fe_copy(h->X,acc.X); fe_copy(h->Y,acc.Y);
    fe_copy(h->Z,acc.Z); fe_copy(h->T,acc.T);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

/*
 * ed25519_ref10_keypair:
 *   pk[32]    = compressed public key (output)
 *   sk[64]    = seed || pk  (NaCl convention) (output)
 *   seed[32]  = random 32-byte value from CSPRNG (input)
 */
static void ed25519_ref10_keypair(
    unsigned char *pk,
    unsigned char *sk,
    const unsigned char *seed)
{
    r10u8 az[64];
    ge_p3 A;

    /* az = SHA-512(seed) */
    sha512_hash(az,(const r10u8*)seed,32);

    /* Scalar clamp (RFC 8032 §5.1.5) */
    az[0]  &= 248;
    az[31] &= 127;
    az[31] |= 64;

    /* A = scalar(az[0..31]) * B */
    ge_scalarmult_base(&A, az);

    /* Encode A */
    ge_p3_tobytes((r10u8*)pk, &A);

    /* sk = seed || pk */
    memcpy(sk,      seed, 32);
    memcpy(sk + 32, pk,   32);
}

#endif /* ED25519_REF10_H */
