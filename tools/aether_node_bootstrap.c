/*
 * aether_node_bootstrap.c -- Cross-platform C bootstrap for Aether node.
 * C89, no external libraries (stdlib + POSIX/Win32 only).
 *
 * Reads: data/interbus/vault_probe_verdict.json  (written by vault_probe.c)
 * Writes: data/interbus/bootstrap_status.json
 *         ~/.aether/vault/node_identity.aek      (only when capability == 1)
 *
 * Exit codes: 0 = success, 1 = fatal error.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <wincrypt.h>
#  pragma comment(lib,"advapi32.lib")
#  define ACCESS_F_OK 0
static int r_access(const char *p,int m){return _access(p,m);}
static void r_mkdir(const char *p){CreateDirectoryA(p,NULL);}
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  define ACCESS_F_OK F_OK
static int r_access(const char *p,int m){return access(p,m);}
static void r_mkdir(const char *p){mkdir(p,0700);}
#endif

#include "ed25519_ref10.h"

/* ── SHA-256 (for AEK checksum) ─────────────────────────────────────────── */

#define S32(x,n)(((x)>>(n))|((x)<<(32-(n))))
#define H256_CH(e,f,g) (((e)&(f))^(~(e)&(g)))
#define H256_MAJ(a,b,c)(((a)&(b))^((a)&(c))^((b)&(c)))
#define H256_S0(a)(S32(a,2)^S32(a,13)^S32(a,22))
#define H256_S1(e)(S32(e,6)^S32(e,11)^S32(e,25))
#define H256_s0(w)(S32(w,7)^S32(w,18)^((w)>>3))
#define H256_s1(w)(S32(w,17)^S32(w,19)^((w)>>10))

static const r10u32 K256[64]={
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
    0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
    0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
    0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
    0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
    0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
    0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
    0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
    0x90beffcaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

typedef struct{r10u32 st[8];r10u32 bc;unsigned char buf[64];r10u32 bl;} sha256_ctx;

static void sha256_compress(sha256_ctx *c, const unsigned char *blk)
{
    r10u32 w[64],a,b,cv,d,e,fv,g,h,t1,t2;
    int i;
    for(i=0;i<16;i++){int j=i*4;w[i]=((r10u32)blk[j]<<24)|((r10u32)blk[j+1]<<16)|((r10u32)blk[j+2]<<8)|(r10u32)blk[j+3];}
    for(i=16;i<64;i++) w[i]=H256_s1(w[i-2])+w[i-7]+H256_s0(w[i-15])+w[i-16];
    a=c->st[0];b=c->st[1];cv=c->st[2];d=c->st[3];
    e=c->st[4];fv=c->st[5];g=c->st[6];h=c->st[7];
    for(i=0;i<64;i++){
        t1=h+H256_S1(e)+H256_CH(e,fv,g)+K256[i]+w[i];
        t2=H256_S0(a)+H256_MAJ(a,b,cv);
        h=g;g=fv;fv=e;e=d+t1;d=cv;cv=b;b=a;a=t1+t2;
    }
    c->st[0]+=a;c->st[1]+=b;c->st[2]+=cv;c->st[3]+=d;
    c->st[4]+=e;c->st[5]+=fv;c->st[6]+=g;c->st[7]+=h;
}

static void sha256_init(sha256_ctx *c)
{
    c->st[0]=0x6a09e667UL;c->st[1]=0xbb67ae85UL;
    c->st[2]=0x3c6ef372UL;c->st[3]=0xa54ff53aUL;
    c->st[4]=0x510e527fUL;c->st[5]=0x9b05688cUL;
    c->st[6]=0x1f83d9abUL;c->st[7]=0x5be0cd19UL;
    c->bc=0;c->bl=0;
}

static void sha256_update(sha256_ctx *c, const unsigned char *in, r10u32 len)
{
    r10u32 left=(r10u32)(64-c->bl);
    c->bc+=len*8;
    if(len>=left){
        memcpy(c->buf+c->bl,in,left);
        sha256_compress(c,c->buf);
        in+=left;len-=left;c->bl=0;
        while(len>=64){sha256_compress(c,in);in+=64;len-=64;}
    }
    memcpy(c->buf+c->bl,in,len);c->bl+=len;
}

static void sha256_final(sha256_ctx *c, unsigned char out[32])
{
    unsigned char pad[64];
    r10u32 pl;
    int i;
    memset(pad,0,64);pad[0]=0x80;
    pl=(c->bl<56)?(r10u32)(56-c->bl):(r10u32)(120-c->bl);
    sha256_update(c,pad,pl);
    pad[0]=pad[1]=pad[2]=pad[3]=0;
    pad[4]=(unsigned char)(c->bc>>24);pad[5]=(unsigned char)(c->bc>>16);
    pad[6]=(unsigned char)(c->bc>>8); pad[7]=(unsigned char)(c->bc);
    sha256_update(c,pad,8);
    for(i=0;i<8;i++){out[i*4]=(unsigned char)(c->st[i]>>24);out[i*4+1]=(unsigned char)(c->st[i]>>16);out[i*4+2]=(unsigned char)(c->st[i]>>8);out[i*4+3]=(unsigned char)(c->st[i]);}
}

static void sha256_of(unsigned char out[32], const unsigned char *in, r10u32 len)
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c,in,len);
    sha256_final(&c,out);
}

/* ── CSPRNG ──────────────────────────────────────────────────────────────── */

static int csprng_fill(unsigned char *buf, size_t len)
{
#ifdef _WIN32
    HCRYPTPROV hProv=0;
    BOOL ok;
    ok=CryptAcquireContextA(&hProv,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT);
    if(!ok) return -1;
    ok=CryptGenRandom(hProv,(DWORD)len,buf);
    CryptReleaseContext(hProv,0);
    return ok?0:-1;
#else
    FILE *f=fopen("/dev/urandom","rb");
    size_t n;
    if(!f) return -1;
    n=fread(buf,1,len,f);
    fclose(f);
    return (n==len)?0:-1;
#endif
}

/* ── Path helpers ────────────────────────────────────────────────────────── */

static void get_home(char *buf, size_t sz)
{
    const char *h;
#ifdef _WIN32
    h=getenv("USERPROFILE");
    if(!h) h="C:\\Users\\Default";
#else
    h=getenv("HOME");
    if(!h) h="/tmp";
#endif
    strncpy(buf,h,sz-1);
    buf[sz-1]='\0';
}

static void mkdir_recursive(const char *path)
{
    char tmp[512];
    char *p;
    strncpy(tmp,path,sizeof(tmp)-1);
    tmp[sizeof(tmp)-1]='\0';
    for(p=tmp+1;*p;p++){
        if(*p=='/'||*p=='\\'){
            *p='\0';
            r_mkdir(tmp);
            *p='/';
        }
    }
    r_mkdir(tmp);
}

/* ── Verdict parsing (minimal JSON field extraction) ─────────────────────── */

static int read_verdict_action(const char *path, char *action, size_t maxlen)
{
    FILE *f;
    char buf[2048];
    size_t n;
    char *p, *q;
    memset(buf,0,sizeof(buf));
    action[0]='\0';
    f=fopen(path,"r");
    if(!f) return -1;
    n=fread(buf,1,sizeof(buf)-1,f);
    fclose(f);
    buf[n]='\0';
    p=strstr(buf,"\"action\"");
    if(!p) return -1;
    p=strchr(p,':');
    if(!p) return -1;
    p++;
    while(*p==' '||*p=='\t') p++;
    if(*p!='"') return -1;
    p++;
    q=strchr(p,'"');
    if(!q) return -1;
    if((size_t)(q-p)>=maxlen) return -1;
    memcpy(action,p,(size_t)(q-p));
    action[q-p]='\0';
    return 0;
}

/* ── Capability test ─────────────────────────────────────────────────────── */

static int cmd_exists(const char *name)
{
#ifdef _WIN32
    char cmd[256];
    snprintf(cmd,sizeof(cmd),"where %s >nul 2>&1",name);
    return (system(cmd)==0)?1:0;
#else
    char cmd[256];
    snprintf(cmd,sizeof(cmd),"command -v %s >/dev/null 2>&1",name);
    return (system(cmd)==0)?1:0;
#endif
}

static int capability_test(void)
{
    int has_iced, has_python, has_ygg;
#ifdef _WIN32
    has_iced  =cmd_exists("aether_iced.exe")||cmd_exists("aether_iced");
#else
    has_iced  =cmd_exists("aether_iced");
#endif
    has_python=cmd_exists("python")||cmd_exists("python3");
    has_ygg   =cmd_exists("yggdrasil");
    return (has_iced && has_python && has_ygg)?1:0;
}

/* ── AEK file creation ───────────────────────────────────────────────────── */

/* AEK layout (96 bytes):
 *   [0..3]   "AEKP" magic
 *   [4..7]   version = 1 (uint32 LE)
 *   [8..39]  Ed25519 seed (32 bytes, random)
 *   [40..71] Ed25519 public key (32 bytes)
 *   [72..79] creation timestamp (uint64 LE, seconds since epoch)
 *   [80..95] SHA-256(bytes 0..79)[0..15]
 */
static int write_aek_file(const char *path)
{
    unsigned char aek[96];
    unsigned char seed[32];
    unsigned char pk[32];
    unsigned char sk[64];
    unsigned char cksum[32];
    unsigned long long ts;
    FILE *f;
    int i;

    if(csprng_fill(seed,32)!=0) return -1;

    ed25519_ref10_keypair(pk,sk,seed);

    memset(aek,0,sizeof(aek));
    aek[0]='A';aek[1]='E';aek[2]='K';aek[3]='P';
    aek[4]=1;aek[5]=0;aek[6]=0;aek[7]=0;
    memcpy(aek+8, seed, 32);
    memcpy(aek+40, pk,   32);

    ts=(unsigned long long)time(NULL);
    for(i=0;i<8;i++) aek[72+i]=(unsigned char)(ts>>(i*8));

    sha256_of(cksum,aek,80);
    memcpy(aek+80,cksum,16);

    f=fopen(path,"wb");
    if(!f) return -1;
    fwrite(aek,1,96,f);
    fclose(f);
    return 0;
}

static int create_aek_if_needed(void)
{
    char home[512];
    char dir[600];
    char aek_path[700];

    get_home(home,sizeof(home));

#ifdef _WIN32
    snprintf(dir,sizeof(dir),"%s\\.aether\\vault",home);
    snprintf(aek_path,sizeof(aek_path),"%s\\node_identity.aek",dir);
    {char d1[600]; snprintf(d1,sizeof(d1),"%s\\.aether",home); r_mkdir(d1);}
#else
    snprintf(dir,sizeof(dir),"%s/.aether/vault",home);
    snprintf(aek_path,sizeof(aek_path),"%s/node_identity.aek",dir);
    {char d1[600]; snprintf(d1,sizeof(d1),"%s/.aether",home); r_mkdir(d1);}
#endif

    r_mkdir(dir);

    if(r_access(aek_path,ACCESS_F_OK)==0) return 0;
    return write_aek_file(aek_path);
}

/* ── Bootstrap status writer ─────────────────────────────────────────────── */

static void write_bootstrap_status(const char *path,
                                   const char *mode,
                                   int capability)
{
    char dir[512];
    FILE *f;
    char *p;
    strncpy(dir,path,sizeof(dir)-1);
    dir[sizeof(dir)-1]='\0';
    p=strrchr(dir,'/');
    if(!p) p=strrchr(dir,'\\');
    if(p){*p='\0'; mkdir_recursive(dir);}

    f=fopen(path,"w");
    if(!f) return;
    fprintf(f,"{\n  \"mode\": \"%s\",\n  \"capability\": %d,\n  \"ts\": %ld\n}\n",
            mode, capability, (long)time(NULL));
    fclose(f);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(void)
{
    char verdict_path[512];
    char status_path[512];
    char action[64];
    int capability;
    const char *mode;
    int has_verdict;

    /* Paths relative to CWD (repo root) */
    strncpy(verdict_path,"data/interbus/vault_probe_verdict.json",sizeof(verdict_path)-1);
    strncpy(status_path, "data/interbus/bootstrap_status.json",   sizeof(status_path)-1);

    has_verdict=(read_verdict_action(verdict_path,action,sizeof(action))==0);
    capability =capability_test();

    /* Mode decision */
    if(capability==1) {
        mode="full";
    } else if(has_verdict && strcmp(action,"linux_fallback")==0) {
        mode="linux_fallback";
    } else if(has_verdict && strcmp(action,"inject_and_retry")==0) {
        mode="learn";
    } else {
        mode="learn";
    }

    /* Create AEK only in full mode */
    if(capability==1) {
        if(create_aek_if_needed()!=0){
            fputs("bootstrap: WARNING: could not create AEK\n",stderr);
        }
    }

    write_bootstrap_status(status_path, mode, capability);
    fprintf(stdout,"bootstrap: mode=%s capability=%d\n", mode, capability);
    return 0;
}
