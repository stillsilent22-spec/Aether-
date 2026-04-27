/*
 * aether_file_converter.c  --  Pre-fallback file converter for Aether.
 * C89, no external libraries (stdlib + POSIX/Win32 only).
 *
 * Must compile and run on Windows 95/98/XP (MinGW / MSVC 6).
 *
 * Purpose:
 *   Converts vault .bin files and probe metrics to a single
 *   "Aether Exchange Format" (.aef) binary before the Linux fallback.
 *   Python and Rust can read this file after the node boots into Linux.
 *
 * Reads:
 *   data\interbus\aether_conversion_request.json  (gate: requested == true)
 *   data\interbus\vault_probe_verdict.json         (12 structural metrics)
 *   data\vault\*.bin                               (vault seed / pattern bins)
 *
 * Writes:
 *   data\vault\export\aether_vault.aef             (AEF binary)
 *   data\interbus\conversion_result.json           (status report)
 *
 * AEF Binary Format v1 (Aether Exchange Format):
 *   [0..3]   "AETH" magic
 *   [4]      version = 0x01
 *   [5]      flags   = 0x00  (reserved)
 *   [6]      metric_count  N  (u8)
 *   [7]      node_info_len L  (u8, 0 for pre-swarm nodes)
 *   [8..8+L) node_info bytes  (ASCII string, empty pre-swarm)
 *   per metric (N entries):
 *     [1 byte]  key_len
 *     [key_len] key  (ASCII metric name, e.g. "entropy_shannon")
 *     [8 bytes] value (double, IEEE 754 little-endian)
 *   [2 bytes]  vault_file_count (u16 LE)
 *   per vault file:
 *     [1 byte]  name_len
 *     [name_len] filename (basename only, no path)
 *     [4 bytes]  data_len (u32 LE)
 *     [data_len] raw file bytes
 *   [2 bytes]  CRC16/XMODEM over ALL preceding bytes  (no SHA, no crypto)
 *
 * No SHA, no encryption.  Integrity = CRC16/XMODEM only.
 * Encryption becomes relevant only after the node joins the swarm.
 *
 * Build (MinGW):
 *   gcc -ansi -Wall -O2 -o bin/aether_file_converter.exe tools/aether_file_converter.c
 * Build (MSVC 6):
 *   cl /W3 /Febin\aether_file_converter.exe tools\aether_file_converter.c
 * Build (POSIX):
 *   gcc -ansi -Wall -O2 -o bin/aether_file_converter tools/aether_file_converter.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  define R_MKDIR(p)  CreateDirectoryA((p), NULL)
#  define SNPRINTF    _snprintf
static const char PATH_CONVERT_REQ[] = "data\\interbus\\aether_conversion_request.json";
static const char PATH_VERDICT[]     = "data\\interbus\\vault_probe_verdict.json";
static const char PATH_VAULT_DIR[]   = "data\\vault";
static const char PATH_EXPORT_DIR[]  = "data\\vault\\export";
static const char PATH_AEF_OUT[]     = "data\\vault\\export\\aether_vault.aef";
static const char PATH_RESULT[]      = "data\\interbus\\conversion_result.json";
#else
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <dirent.h>
#  define R_MKDIR(p)  mkdir((p), 0755)
#  define SNPRINTF    snprintf
static const char PATH_CONVERT_REQ[] = "data/interbus/aether_conversion_request.json";
static const char PATH_VERDICT[]     = "data/interbus/vault_probe_verdict.json";
static const char PATH_VAULT_DIR[]   = "data/vault";
static const char PATH_EXPORT_DIR[]  = "data/vault/export";
static const char PATH_AEF_OUT[]     = "data/vault/export/aether_vault.aef";
static const char PATH_RESULT[]      = "data/interbus/conversion_result.json";
#endif

/* ── Type aliases (C89 / no stdint.h) ───────────────────────────────────── */
typedef unsigned char   u8;
typedef unsigned short  u16;
typedef unsigned long   u32;

/* ── CRC16/XMODEM ────────────────────────────────────────────────────────── */
/*
 * Polynomial: 0x1021
 * Init:       0x0000
 * RefIn:      false
 * RefOut:     false
 * XorOut:     0x0000
 */
static u16 crc16_update(u16 crc, u8 byte_val)
{
    int i;
    crc ^= (u16)((u16)byte_val << 8);
    for (i = 0; i < 8; i++) {
        if (crc & 0x8000u) {
            crc = (u16)((crc << 1) ^ 0x1021u);
        } else {
            crc = (u16)(crc << 1);
        }
    }
    return crc;
}

static u16 crc16_buf(const u8 *data, u32 len)
{
    u16  crc = 0x0000u;
    u32  i;
    for (i = 0; i < len; i++) {
        crc = crc16_update(crc, data[i]);
    }
    return crc;
}

/* ── Minimal JSON helpers ────────────────────────────────────────────────── */

/*
 * Returns 1 if "field": true, 0 if "field": false, -1 if not found.
 */
static int json_bool_field(const char *buf, const char *field)
{
    const char *p;
    p = strstr(buf, field);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (strncmp(p, "true",  4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    return -1;
}

/*
 * Writes the double value of "field": <number> into *out.
 * Returns 0 on success, -1 if field not found.
 */
static int json_double_field(const char *buf, const char *field, double *out)
{
    const char *p;
    p = strstr(buf, field);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    *out = atof(p);
    return 0;
}

/* ── File I/O helpers ────────────────────────────────────────────────────── */

/*
 * Read entire file into a malloc'd buffer.  Appends NUL so it can be
 * used as a C string.  Caller must free().  Returns NULL on error.
 * Max size enforced to 64 MB to prevent integer overflow on legacy hardware.
 */
static u8 *read_file_alloc(const char *path, u32 *out_len)
{
    FILE  *f;
    long   sz;
    u8    *buf;
    size_t n;

    f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz < 0L || sz > 67108864L) { fclose(f); return NULL; } /* 64 MB cap */
    rewind(f);

    buf = (u8 *)malloc((size_t)sz + 1u);
    if (!buf) { fclose(f); return NULL; }

    n = fread(buf, 1u, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    *out_len = (u32)n;
    return buf;
}

/* ── Double → little-endian 8 bytes (IEEE 754) ───────────────────────────── */
/*
 * C89-portable: copies via memcpy (avoids aliasing UB), then reverses
 * on big-endian hosts.  On Win95/98/XP (x86) the bytes are already LE.
 */
static void double_to_le8(double v, u8 out[8])
{
    unsigned char tmp[8];
    int i;
    u32 test = 1u;
    unsigned char *tp = (unsigned char *)&test;

    memcpy(tmp, &v, 8u);
    if (tp[0] == 1) {
        /* Little-endian host */
        for (i = 0; i < 8; i++) out[i] = tmp[i];
    } else {
        /* Big-endian host */
        for (i = 0; i < 8; i++) out[i] = tmp[7 - i];
    }
}

/* ── Dynamic output buffer ───────────────────────────────────────────────── */

typedef struct {
    u8  *data;
    u32  len;
    u32  cap;
} OutBuf;

static int ob_init(OutBuf *ob, u32 initial_cap)
{
    ob->data = (u8 *)malloc((size_t)initial_cap);
    if (!ob->data) return -1;
    ob->len = 0u;
    ob->cap = initial_cap;
    return 0;
}

static void ob_free(OutBuf *ob)
{
    if (ob->data) { free(ob->data); ob->data = NULL; }
    ob->len = ob->cap = 0u;
}

static int ob_grow(OutBuf *ob, u32 needed)
{
    u32  newcap;
    u8  *newdata;
    newcap = ob->cap;
    while (newcap < needed) newcap *= 2u;
    newdata = (u8 *)realloc(ob->data, (size_t)newcap);
    if (!newdata) return -1;
    ob->data = newdata;
    ob->cap  = newcap;
    return 0;
}

static int ob_push(OutBuf *ob, const u8 *bytes, u32 n)
{
    u32 needed = ob->len + n;
    if (needed > ob->cap && ob_grow(ob, needed) != 0) return -1;
    memcpy(ob->data + ob->len, bytes, (size_t)n);
    ob->len += n;
    return 0;
}

static int ob_push_u8(OutBuf *ob, u8 b)
{
    return ob_push(ob, &b, 1u);
}

static int ob_push_u16le(OutBuf *ob, u16 v)
{
    u8 bytes[2];
    bytes[0] = (u8)( v        & 0xFFu);
    bytes[1] = (u8)((v >> 8u) & 0xFFu);
    return ob_push(ob, bytes, 2u);
}

static int ob_push_u32le(OutBuf *ob, u32 v)
{
    u8 bytes[4];
    bytes[0] = (u8)( v         & 0xFFu);
    bytes[1] = (u8)((v >>  8u) & 0xFFu);
    bytes[2] = (u8)((v >> 16u) & 0xFFu);
    bytes[3] = (u8)((v >> 24u) & 0xFFu);
    return ob_push(ob, bytes, 4u);
}

/*
 * Push a length-prefixed byte string: [1 byte len][len bytes data].
 * Strings longer than 255 are silently truncated.
 */
static int ob_push_lenstr(OutBuf *ob, const char *s)
{
    size_t slen = strlen(s);
    u8     lbyte;
    if (slen > 255u) slen = 255u;
    lbyte = (u8)slen;
    if (ob_push_u8(ob, lbyte) != 0) return -1;
    return ob_push(ob, (const u8 *)s, (u32)slen);
}

/* ── Vault file enumeration ───────────────────────────────────────────────── */

#define MAX_VAULT_FILES 64

typedef struct {
    char  name[260];
    u8   *data;
    u32   data_len;
} VaultEntry;

/*
 * Load all *.bin files from PATH_VAULT_DIR into entries[].
 * Returns the number of files loaded.
 */
static int load_vault_files(VaultEntry *entries, int max_entries)
{
    int count = 0;

#ifdef _WIN32
    {
        WIN32_FIND_DATAA fd;
        HANDLE           hFind;
        char             pattern[512];

        SNPRINTF(pattern, sizeof(pattern) - 1, "%s\\*.bin", PATH_VAULT_DIR);
        pattern[sizeof(pattern) - 1] = '\0';

        hFind = FindFirstFileA(pattern, &fd);
        if (hFind == INVALID_HANDLE_VALUE) return 0;

        do {
            char full_path[512];
            u8  *fdata;
            u32  flen;

            if (count >= max_entries) break;
            if (fd.cFileName[0] == '.') continue;

            SNPRINTF(full_path, sizeof(full_path) - 1,
                     "%s\\%s", PATH_VAULT_DIR, fd.cFileName);
            full_path[sizeof(full_path) - 1] = '\0';

            fdata = read_file_alloc(full_path, &flen);
            if (!fdata) {
                printf("[CONVERTER] warning: could not read %s\n", full_path);
                continue;
            }

            strncpy(entries[count].name, fd.cFileName,
                    sizeof(entries[count].name) - 1);
            entries[count].name[sizeof(entries[count].name) - 1] = '\0';
            entries[count].data     = fdata;
            entries[count].data_len = flen;
            count++;
        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    }
#else
    {
        DIR           *d;
        struct dirent *ent;

        d = opendir(PATH_VAULT_DIR);
        if (!d) return 0;

        while ((ent = readdir(d)) != NULL) {
            char        full_path[512];
            const char *dot;
            u8         *fdata;
            u32         flen;

            if (count >= max_entries) break;
            if (ent->d_name[0] == '.') continue;

            dot = strrchr(ent->d_name, '.');
            if (!dot || strcmp(dot, ".bin") != 0) continue;

            SNPRINTF(full_path, sizeof(full_path) - 1,
                     "%s/%s", PATH_VAULT_DIR, ent->d_name);
            full_path[sizeof(full_path) - 1] = '\0';

            fdata = read_file_alloc(full_path, &flen);
            if (!fdata) {
                printf("[CONVERTER] warning: could not read %s\n", full_path);
                continue;
            }

            strncpy(entries[count].name, ent->d_name,
                    sizeof(entries[count].name) - 1);
            entries[count].name[sizeof(entries[count].name) - 1] = '\0';
            entries[count].data     = fdata;
            entries[count].data_len = flen;
            count++;
        }
        closedir(d);
    }
#endif

    return count;
}

/* ── Metrics table ───────────────────────────────────────────────────────── */

typedef struct {
    const char *export_key;  /* key written into .aef */
    const char *json_field;  /* field name in vault_probe_verdict.json */
    double      value;
} MetricEntry;

/* Order must match vault_probe.c write_verdict() output. */
static MetricEntry g_metrics[12];
#define METRIC_COUNT 12

static void init_metrics(void)
{
    g_metrics[0].export_key  = "entropy_shannon";
    g_metrics[0].json_field  = "\"entropy\"";
    g_metrics[0].value       = 0.0;

    g_metrics[1].export_key  = "entropy_boltzmann";
    g_metrics[1].json_field  = "\"boltzmann_entropy\"";
    g_metrics[1].value       = 0.0;

    g_metrics[2].export_key  = "symmetry";
    g_metrics[2].json_field  = "\"symmetry\"";
    g_metrics[2].value       = 0.0;

    g_metrics[3].export_key  = "periodicity";
    g_metrics[3].json_field  = "\"periodicity\"";
    g_metrics[3].value       = 0.0;

    g_metrics[4].export_key  = "zipf_alpha";
    g_metrics[4].json_field  = "\"zipf_alpha\"";
    g_metrics[4].value       = 0.0;

    g_metrics[5].export_key  = "benford_score";
    g_metrics[5].json_field  = "\"benford_score\"";
    g_metrics[5].value       = 0.0;

    g_metrics[6].export_key  = "katz_dimension";
    g_metrics[6].json_field  = "\"katz_dimension\"";
    g_metrics[6].value       = 0.0;

    g_metrics[7].export_key  = "perm_entropy";
    g_metrics[7].json_field  = "\"perm_entropy\"";
    g_metrics[7].value       = 0.0;

    g_metrics[8].export_key  = "xor_delta_ratio";
    g_metrics[8].json_field  = "\"xor_delta_ratio\"";
    g_metrics[8].value       = 0.0;

    g_metrics[9].export_key  = "h_lambda";
    g_metrics[9].json_field  = "\"h_lambda\"";
    g_metrics[9].value       = 0.0;

    g_metrics[10].export_key = "noether_consistency";
    g_metrics[10].json_field = "\"noether_consistency\"";
    g_metrics[10].value      = 0.0;

    g_metrics[11].export_key = "gradient_coherence";
    g_metrics[11].json_field = "\"gradient_coherence\"";
    g_metrics[11].value      = 0.0;
}

/* ── Result writer ───────────────────────────────────────────────────────── */

static void write_result(int success, int vault_files, u32 aef_bytes)
{
    FILE *f = fopen(PATH_RESULT, "wb");
    if (!f) return;
    fprintf(f,
        "{\n"
        "  \"schema\": \"aether.conversion.result.v1\",\n"
        "  \"success\": %s,\n"
        "  \"vault_files_converted\": %d,\n"
        "  \"aef_bytes\": %lu,\n"
        "  \"aef_path\": \"data/vault/export/aether_vault.aef\",\n"
        "  \"ts\": %ld\n"
        "}\n",
        success ? "true" : "false",
        vault_files,
        (unsigned long)aef_bytes,
        (long)time(NULL));
    fclose(f);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(void)
{
    u8         *req_buf;
    u32         req_len;
    u8         *verdict_buf;
    u32         verdict_len;
    int         requested;
    int         i;
    VaultEntry  entries[MAX_VAULT_FILES];
    int         vault_count;
    OutBuf      ob;
    u8          le8[8];
    u16         crc;
    FILE       *fout;
    const char *metrics_block;

    /* ── Step 1: Check conversion flag ───────────────────────────────────── */
    req_buf = read_file_alloc(PATH_CONVERT_REQ, &req_len);
    if (!req_buf) {
        printf("[CONVERTER] conversion request file not found — skipping.\n");
        return 0;
    }
    requested = json_bool_field((const char *)req_buf, "\"requested\"");
    free(req_buf);

    if (requested != 1) {
        printf("[CONVERTER] conversion not requested (requested=%d) — skipping.\n",
               requested);
        return 0;
    }

    printf("[CONVERTER] Aether File Converter v1  (pre-fallback, no SHA)\n");

    /* ── Step 2: Load probe metrics from verdict JSON ────────────────────── */
    init_metrics();

    verdict_buf = read_file_alloc(PATH_VERDICT, &verdict_len);
    if (!verdict_buf) {
        fprintf(stderr, "[CONVERTER] ERROR: vault_probe_verdict.json not found.\n");
        write_result(0, 0, 0u);
        return 1;
    }

    /* Find the "metrics" sub-object and extract each field from inside it. */
    metrics_block = strstr((const char *)verdict_buf, "\"metrics\"");
    if (metrics_block) {
        metrics_block = strchr(metrics_block, '{');
    }

    for (i = 0; i < METRIC_COUNT; i++) {
        double val = 0.0;
        if (metrics_block) {
            json_double_field(metrics_block, g_metrics[i].json_field, &val);
        }
        g_metrics[i].value = val;
    }

    free(verdict_buf);
    printf("[CONVERTER] metrics loaded: %d entries.\n", METRIC_COUNT);

    /* ── Step 3: Enumerate vault .bin files ──────────────────────────────── */
    memset(entries, 0, sizeof(entries));
    vault_count = load_vault_files(entries, MAX_VAULT_FILES);
    printf("[CONVERTER] vault .bin files found: %d\n", vault_count);

    /* ── Step 4: Ensure export directory exists ──────────────────────────── */
    R_MKDIR(PATH_EXPORT_DIR);

    /* ── Step 5: Build AEF binary ────────────────────────────────────────── */
    if (ob_init(&ob, 65536u) != 0) {
        fprintf(stderr, "[CONVERTER] ERROR: out of memory.\n");
        write_result(0, 0, 0u);
        return 1;
    }

    /* Header */
    ob_push_u8(&ob, (u8)'A');
    ob_push_u8(&ob, (u8)'E');
    ob_push_u8(&ob, (u8)'T');
    ob_push_u8(&ob, (u8)'H');
    ob_push_u8(&ob, 0x01u); /* version    */
    ob_push_u8(&ob, 0x00u); /* flags      */
    ob_push_u8(&ob, (u8)METRIC_COUNT);
    ob_push_u8(&ob, 0x00u); /* node_info_len = 0 (no identity pre-swarm) */

    /* Metrics block: [key_len][key][8-byte double LE] */
    for (i = 0; i < METRIC_COUNT; i++) {
        double_to_le8(g_metrics[i].value, le8);
        ob_push_lenstr(&ob, g_metrics[i].export_key);
        ob_push(&ob, le8, 8u);
    }

    /* Vault files: [count u16][name_len][name][data_len u32][data] */
    ob_push_u16le(&ob, (u16)vault_count);
    for (i = 0; i < vault_count; i++) {
        ob_push_lenstr(&ob, entries[i].name);
        ob_push_u32le(&ob, entries[i].data_len);
        ob_push(&ob, entries[i].data, entries[i].data_len);
    }

    /* CRC16/XMODEM footer over all preceding bytes */
    crc = crc16_buf(ob.data, ob.len);
    ob_push_u16le(&ob, crc);

    /* ── Step 6: Write AEF file ──────────────────────────────────────────── */
    fout = fopen(PATH_AEF_OUT, "wb");
    if (!fout) {
        fprintf(stderr, "[CONVERTER] ERROR: cannot create output file: %s\n",
                PATH_AEF_OUT);
        write_result(0, vault_count, 0u);
        ob_free(&ob);
        for (i = 0; i < vault_count; i++) free(entries[i].data);
        return 1;
    }

    fwrite(ob.data, 1u, (size_t)ob.len, fout);
    fclose(fout);

    printf("[CONVERTER] AEF written: %lu bytes  (%d metrics, %d vault files)\n",
           (unsigned long)ob.len, METRIC_COUNT, vault_count);
    printf("[CONVERTER] output: %s\n", PATH_AEF_OUT);
    printf("[CONVERTER] CRC16: 0x%04X\n", (unsigned)crc);

    /* ── Step 7: Write result JSON ───────────────────────────────────────── */
    write_result(1, vault_count, ob.len);

    ob_free(&ob);
    for (i = 0; i < vault_count; i++) {
        if (entries[i].data) free(entries[i].data);
    }

    return 0;
}
