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

/* ── CRC16/XMODEM (replaces SHA-256 for AEK checksum) ───────────────────── */
/*
 * Polynomial: 0x1021  Init: 0x0000  No reflection, no XorOut.
 * Sufficient for a tamper-detection footer on a local identity file.
 * Encryption (including SHA) is only relevant after the node joins the swarm.
 */
static r10u32 aek_crc16_update(r10u32 crc, unsigned char byte_val)
{
    int i;
    crc ^= (r10u32)((r10u32)byte_val << 8);
    for (i = 0; i < 8; i++) {
        if (crc & 0x8000UL) {
            crc = (r10u32)((crc << 1) ^ 0x1021UL);
        } else {
            crc = (r10u32)(crc << 1);
        }
        crc &= 0xFFFFUL;
    }
    return crc;
}

static r10u32 aek_crc16(const unsigned char *data, r10u32 len)
{
    r10u32 crc = 0x0000UL;
    r10u32 i;
    for (i = 0; i < len; i++) {
        crc = aek_crc16_update(crc, data[i]);
    }
    return crc;
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
 *   [80..81] CRC16/XMODEM(bytes 0..79)  -- integrity footer, no SHA
 *   [82..95] zero-padded (reserved)
 */
static int write_aek_file(const char *path)
{
    unsigned char      aek[96];
    unsigned char      seed[32];
    unsigned char      pk[32];
    unsigned char      sk[64];
    r10u32             crc;
    unsigned long long ts;
    FILE              *f;
    int                i;

    if(csprng_fill(seed,32)!=0) return -1;

    ed25519_ref10_keypair(pk,sk,seed);

    memset(aek,0,sizeof(aek));
    aek[0]='A';aek[1]='E';aek[2]='K';aek[3]='P';
    aek[4]=1;aek[5]=0;aek[6]=0;aek[7]=0;
    memcpy(aek+8, seed, 32);
    memcpy(aek+40, pk,   32);

    ts=(unsigned long long)time(NULL);
    for(i=0;i<8;i++) aek[72+i]=(unsigned char)(ts>>(i*8));

    /* CRC16/XMODEM over bytes 0..79 -- replaces SHA-256 checksum */
    crc = aek_crc16(aek, 80u);
    aek[80] = (unsigned char)( crc        & 0xFFu);
    aek[81] = (unsigned char)((crc >> 8u) & 0xFFu);
    /* bytes [82..95] remain zero (reserved) */

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

/* Read a single integer field from a minimal JSON file.
 * Returns the numeric value, or 0 if not found / parse error.
 * Looks for the pattern: "field": <int>
 */
static int read_json_int_field(const char *path, const char *field)
{
    FILE *f;
    char buf[2048];
    size_t n;
    char *p;
    memset(buf, 0, sizeof(buf));
    f = fopen(path, "r");
    if (!f) return 0;
    n = fread(buf, 1, sizeof(buf)-1, f);
    fclose(f);
    buf[n] = '\0';
    p = strstr(buf, field);
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return atoi(p);
}

/* ── Service install prompt ───────────────────────────────────────────────── */
/* Shows a native dialog (Windows) or terminal prompt (POSIX).
 * Returns 1 if the user confirmed, 0 if deferred.
 * linux_fallback_mode=1: message asks about post-Linux autostart.
 * linux_fallback_mode=0: message asks about Windows service install.
 * Only called once: aether_node_bootstrap writes "service_asked":1
 * afterwards so subsequent runs skip the dialog.
 */
static int ask_install_service_dialog(int linux_fallback_mode)
{
#ifdef _WIN32
    int res;
    const char *msg = linux_fallback_mode
        ? "Nach der Linux-Installation: Aether automatisch beim Start starten?\n\n"
          "Das Autostart-Skript wird in die neue Linux-Partition eingetragen.\n"
          "Du kannst es jederzeit im SwarmOps-Tab deaktivieren.\n\n"
          "Ja = automatisch starten     Nein = manuell"
        : "Aether als Windows-Dienst installieren?\n\n"
          "Der Dienst startet automatisch bei jedem Systemstart.\n"
          "Du kannst ihn jederzeit im SwarmOps-Tab deaktivieren.\n\n"
          "Ja = jetzt installieren     Nein = spaeter";
    res = MessageBoxA(
        NULL,
        msg,
        "Aether Setup",
        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2
    );
    return (res == IDYES) ? 1 : 0;
#else
    char input[8];
    int c;
    if (linux_fallback_mode) {
        printf("\nNach dem Linux-Neustart: Aether automatisch starten? [j/N]: ");
    } else {
        printf("\nAether als Systemdienst installieren? [j/N]: ");
    }
    fflush(stdout);
    memset(input, 0, sizeof(input));
    if (fgets(input, sizeof(input), stdin) == NULL) return 0;
    if (strchr(input, '\n') == NULL) {
        while ((c = getchar()) != '\n' && c != EOF) {}
    }
    return (input[0] == 'j' || input[0] == 'J') ? 1 : 0;
#endif
}

static void write_bootstrap_status(const char *path,
                                   const char *mode,
                                   int capability,
                                   int install_service,
                                   int service_asked)
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
    fprintf(f,
        "{\n"
        "  \"mode\": \"%s\",\n"
        "  \"capability\": %d,\n"
        "  \"install_service\": %d,\n"
        "  \"service_asked\": %d,\n"
        "  \"ts\": %ld\n"
        "}\n",
        mode, capability, install_service, service_asked, (long)time(NULL));
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
    int install_service;
    int service_asked;

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

    /* Service install dialog -- shown exactly once for full or linux_fallback mode.
     * If the user already answered, preserve the previous answer.
     * service_asked=1 prevents re-showing the dialog on subsequent starts.
     */
    service_asked   = read_json_int_field(status_path, "\"service_asked\"");
    install_service = read_json_int_field(status_path, "\"install_service\"");
    if(!service_asked &&
       (capability==1 || strcmp(mode,"linux_fallback")==0)) {
        int is_fallback = (strcmp(mode,"linux_fallback")==0) ? 1 : 0;
        install_service = ask_install_service_dialog(is_fallback);
        service_asked   = 1;
    }

    write_bootstrap_status(status_path, mode, capability, install_service, service_asked);
    fprintf(stdout,"bootstrap: mode=%s capability=%d install_service=%d\n",
            mode, capability, install_service);
    return 0;
}
