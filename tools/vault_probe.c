/*
 * vault_probe.c
 *
 * Standalone legacy probe for Windows 95/98/ME/2000/XP and newer.
 * No Python, no .NET, no external runtime dependencies.
 *
 * Purpose:
 *   - Reuse core AE/AELab structural metrics in plain C.
 *   - Decide whether a legacy node is ready for Linux fallback.
 *   - If not ready: inject deterministic vault seed logic and enforce
 *     a 24h retry window.
 *   - Ask for Aether format conversion request before Linux fallback.
 *
 * Build:
 *   MinGW: gcc -ansi -Wall -O2 -o vault_probe.exe vault_probe.c
 *   MSVC6: cl /W3 vault_probe.c
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

/* ANSI C89 compatible integer aliases */
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned long  u32;

/* Configuration */
#define VAULT_PATTERN_THRESHOLD  8
#define VAULT_MIN_COUNT          3
#define RAM_MIN_FREE_KB          49152
#define COMPRESS_TARGET_RATIO    70
#define MAX_PATTERNS             8192
#define MAX_SAMPLE_BYTES         (1024u * 1024u)
#define ENTROPY_BLOCK_SIZE       256
#define MAX_ENTROPY_BLOCKS       4096
#define TEST_BUF_KB              64
#define MAX_PATH_LEN             512
#define RETRY_SECONDS            (24L * 60L * 60L)

/* AELab anchor masks */
#define AM_PI      (1u << 0)
#define AM_E       (1u << 1)
#define AM_POW2    (1u << 2)
#define AM_BINMASK (1u << 3)
#define AM_THRESH  (1u << 4)

/* Paths */
static const char PATH_DATA[]            = "data";
static const char PATH_VAULT_DIR[]       = "data\\vault";
static const char PATH_INTERBUS_DIR[]    = "data\\interbus";
static const char PATH_VERDICT[]         = "data\\interbus\\vault_probe_verdict.json";
static const char PATH_RETRY_LOCK[]      = "data\\interbus\\vault_probe_retry.lock";
static const char PATH_CONVERT_REQ[]     = "data\\interbus\\aether_conversion_request.json";
static const char PATH_VAULT_SEED[]      = "data\\vault\\aether_seed_v1.bin";

typedef struct {
    u32 key;
    u32 count;
} PatternEntry;

typedef struct {
    double entropy_shannon;
    double entropy_boltzmann;
    double symmetry;
    double periodicity;
    double zipf_alpha;
    double benford_score;
    double katz_dimension;
    double perm_entropy;
    double xor_delta_ratio;
    double h_lambda;
    double noether_consistency;
    double gradient_coherence;
} ProbeMetrics;

typedef struct {
    ProbeMetrics metrics;
    int vault_ready;
    int ram_ok;
    int compress_ok;
    int metric_ok;
    int strong_patterns;
    int files_scanned;
    int compress_ratio_pct;
    u32 free_kb;
    u32 mem_load_pct;
    unsigned anchor_mask;
    int anchor_hits;
    double sce_score;
    double trust_score;
    double invariant_strength;
    const char *action;
    int conversion_requested; /* -1 unknown */
    long retry_after_sec;
    int injected_seed;
    const char *recommended_linux_distro; /* set when action == "linux_fallback" */
    int yggdrasil_recommended; /* 1 = install Yggdrasil regardless of OS */
} ProbeVerdict;

/* Global scan state */
static PatternEntry g_patterns[MAX_PATTERNS];
static u32 g_byte_counts[256];
static u8 g_sample[MAX_SAMPLE_BYTES];
static u32 g_sample_len = 0;
static u32 g_total_bytes = 0;
static unsigned g_anchor_mask = 0;
static int g_anchor_hits = 0;

static double clampd(double value, double low, double high) {
    if (value < low) return low;
    if (value > high) return high;
    return value;
}

static double clamp01(double value) {
    return clampd(value, 0.0, 1.0);
}

static double log2_compat(double value) {
    if (value <= 0.0) return 0.0;
    return log(value) / log(2.0);
}

static void ensure_base_dirs(void) {
    CreateDirectoryA(PATH_DATA, NULL);
    CreateDirectoryA(PATH_VAULT_DIR, NULL);
    CreateDirectoryA(PATH_INTERBUS_DIR, NULL);
}

static void iso_timestamp(char *buf, int buflen) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    _snprintf(
        buf,
        buflen - 1,
        "%04d-%02d-%02dT%02d:%02d:%02dZ",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond
    );
    buf[buflen - 1] = '\0';
}

static long now_epoch_seconds(void) {
    time_t now;
    now = time(NULL);
    if (now == (time_t)-1) return 0L;
    return (long)now;
}

static int read_retry_lock(long *out_epoch) {
    FILE *f;
    char line[64];
    long ts;
    f = fopen(PATH_RETRY_LOCK, "rb");
    if (!f) return 0;
    line[0] = '\0';
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    ts = atol(line);
    if (ts <= 0) return 0;
    *out_epoch = ts;
    return 1;
}

static int retry_window_active(long now, long *out_remaining) {
    long base;
    long until;
    if (!read_retry_lock(&base)) return 0;
    until = base + RETRY_SECONDS;
    if (now < until) {
        *out_remaining = until - now;
        return 1;
    }
    DeleteFileA(PATH_RETRY_LOCK);
    return 0;
}

static void write_retry_lock(long now) {
    FILE *f;
    ensure_base_dirs();
    f = fopen(PATH_RETRY_LOCK, "wb");
    if (!f) return;
    fprintf(f, "%ld\n", now);
    fclose(f);
}

static void reset_scan_state(void) {
    memset(g_patterns, 0, sizeof(g_patterns));
    memset(g_byte_counts, 0, sizeof(g_byte_counts));
    g_sample_len = 0;
    g_total_bytes = 0;
    g_anchor_mask = 0;
    g_anchor_hits = 0;
}

static void pattern_insert(u32 key) {
    int i;
    int slot;
    slot = (int)(key % (u32)MAX_PATTERNS);
    for (i = 0; i < MAX_PATTERNS; i++) {
        int idx;
        idx = (slot + i) % MAX_PATTERNS;
        if (g_patterns[idx].count == 0) {
            g_patterns[idx].key = key;
            g_patterns[idx].count = 1;
            return;
        }
        if (g_patterns[idx].key == key) {
            g_patterns[idx].count++;
            return;
        }
    }
    g_patterns[slot].key = key;
    g_patterns[slot].count = 1;
}

static unsigned anchor_mask_for_value(double value) {
    double av;
    unsigned mask;
    long iv;

    av = value;
    if (av < 0.0) av = -av;
    mask = 0u;

    if (fabs(av - 3.141592653589793) < 0.02) mask |= AM_PI;
    if (fabs(av - 2.718281828459045) < 0.02) mask |= AM_E;
    if (fabs(av - 0.25) < 0.03 || fabs(av - 0.50) < 0.03 ||
        fabs(av - 0.75) < 0.03 || fabs(av - 1.00) < 0.03) {
        mask |= AM_THRESH;
    }

    iv = (long)(av + 0.5);
    if (iv > 0 && fabs(av - (double)iv) < 1e-6) {
        unsigned long u;
        u = (unsigned long)iv;
        if ((u & (u - 1u)) == 0u) mask |= AM_POW2;
        if (u == 15u || u == 31u || u == 63u || u == 127u || u == 255u) {
            mask |= AM_BINMASK;
        }
    }
    return mask;
}

static unsigned anchor_mask_for_key(u32 key) {
    union {
        u32 u;
        float f;
    } cv;
    double as_float;
    unsigned mask;

    cv.u = key;
    as_float = (double)cv.f;
    if (!(as_float == as_float) || as_float > 1e9 || as_float < -1e9) {
        as_float = (double)(key & 0xFFu);
    }
    mask = anchor_mask_for_value(as_float);
    if (mask == 0u) {
        mask = anchor_mask_for_value((double)(key & 0xFFu));
    }
    return mask;
}

static void scan_file(const char *path) {
    FILE *f;
    u8 buf[4096];
    size_t nread;
    u8 win[4];
    int win_fill;

    f = fopen(path, "rb");
    if (!f) return;

    win_fill = 0;
    while (1) {
        u32 i;
        nread = fread(buf, 1, sizeof(buf), f);
        if (nread == 0) break;

        for (i = 0; i < (u32)nread; i++) {
            u8 b;
            b = buf[i];
            g_total_bytes++;
            g_byte_counts[(int)b]++;
            if (g_sample_len < MAX_SAMPLE_BYTES) {
                g_sample[g_sample_len++] = b;
            }

            win[win_fill++] = b;
            if (win_fill == 4) {
                u32 key;
                unsigned am;
                key = ((u32)win[0]) |
                      ((u32)win[1] << 8) |
                      ((u32)win[2] << 16) |
                      ((u32)win[3] << 24);
                pattern_insert(key);
                am = anchor_mask_for_key(key);
                if (am != 0u) {
                    g_anchor_mask |= am;
                    g_anchor_hits++;
                }
                win[0] = win[1];
                win[1] = win[2];
                win[2] = win[3];
                win_fill = 3;
            }
        }
    }
    fclose(f);
}

static int scan_vault_dir(const char *dir) {
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    char glob[MAX_PATH_LEN];
    char full[MAX_PATH_LEN];
    int count;

    count = 0;
    _snprintf(glob, sizeof(glob) - 1, "%s\\*", dir);
    glob[sizeof(glob) - 1] = '\0';

    hFind = FindFirstFileA(glob, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) {
            continue;
        }
        _snprintf(full, sizeof(full) - 1, "%s\\%s", dir, fd.cFileName);
        full[sizeof(full) - 1] = '\0';

        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            count += scan_vault_dir(full);
        } else {
            scan_file(full);
            count++;
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return count;
}

static int count_strong_patterns(void) {
    int i;
    int n;
    n = 0;
    for (i = 0; i < MAX_PATTERNS; i++) {
        if (g_patterns[i].count >= (u32)VAULT_MIN_COUNT) n++;
    }
    return n;
}

static double entropy_of_buffer(const u8 *data, u32 len) {
    u32 counts[256];
    u32 i;
    double total;
    double h;

    if (!data || len == 0) return 0.0;
    memset(counts, 0, sizeof(counts));
    for (i = 0; i < len; i++) {
        counts[(int)data[i]]++;
    }
    total = (double)len;
    h = 0.0;
    for (i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p;
            p = (double)counts[i] / total;
            h -= p * log2_compat(p);
        }
    }
    return h;
}

static double shannon_entropy_counts(void) {
    u32 i;
    double total;
    double h;

    if (g_total_bytes == 0) return 0.0;
    total = (double)g_total_bytes;
    h = 0.0;
    for (i = 0; i < 256; i++) {
        if (g_byte_counts[i] > 0) {
            double p;
            p = (double)g_byte_counts[i] / total;
            h -= p * log2_compat(p);
        }
    }
    return h;
}

static double boltzmann_entropy_counts(void) {
    u32 i;
    double total;
    double s;

    if (g_total_bytes == 0) return 0.0;
    total = (double)g_total_bytes;
    s = 0.0;
    for (i = 0; i < 256; i++) {
        if (g_byte_counts[i] > 0) {
            double p;
            p = (double)g_byte_counts[i] / total;
            s -= p * log(p);
        }
    }
    return clamp01(s / log(256.0));
}

static double symmetry_score_counts(void) {
    u32 i;
    double non_zero_sum;
    double non_zero_count;
    double mean;
    double deviation;

    if (g_total_bytes == 0) return 1.0;

    non_zero_sum = 0.0;
    non_zero_count = 0.0;
    for (i = 0; i < 256; i++) {
        if (g_byte_counts[i] > 0) {
            non_zero_sum += (double)g_byte_counts[i];
            non_zero_count += 1.0;
        }
    }
    if (non_zero_count <= 0.0) return 1.0;

    mean = non_zero_sum / non_zero_count;
    deviation = 0.0;
    for (i = 0; i < 256; i++) {
        if (g_byte_counts[i] > 0) {
            deviation += fabs((double)g_byte_counts[i] - mean);
        }
    }
    deviation /= non_zero_count;
    return clamp01(1.0 - deviation / ((mean > 1.0) ? mean : 1.0));
}

static double lag_periodicity_score(void) {
    u32 n;
    u32 lag;
    double best;
    u32 max_lag;

    n = g_sample_len;
    if (n < 4) return 0.0;

    max_lag = n / 3;
    if (max_lag < 2) max_lag = 2;
    if (max_lag > 64) max_lag = 64;

    best = 0.0;
    for (lag = 1; lag <= max_lag; lag++) {
        u32 comparisons;
        u32 i;
        u32 matches;
        double score;

        comparisons = n - lag;
        if (comparisons == 0) continue;
        matches = 0;
        for (i = 0; i < comparisons; i++) {
            if (g_sample[i] == g_sample[i + lag]) matches++;
        }
        score = (double)matches / (double)comparisons;
        if (score > best) best = score;
    }
    return clamp01(best);
}

static double xor_delta_ratio(void) {
    u32 i;
    u32 changed;

    if (g_sample_len == 0) return 0.0;
    changed = 1;
    for (i = 1; i < g_sample_len; i++) {
        if ((u8)(g_sample[i] ^ g_sample[i - 1]) != 0u) changed++;
    }
    return (double)changed / (double)g_sample_len;
}

static int first_digit_u32(u32 value) {
    while (value >= 10u) value /= 10u;
    return (int)value;
}

static double benford_score_sample(void) {
    u32 i;
    u32 total;
    u32 counts[10];
    double chi;

    memset(counts, 0, sizeof(counts));
    total = 0;
    for (i = 0; i + 3 < g_sample_len; i += 4) {
        u32 v;
        int d;
        v = ((u32)g_sample[i] << 24) |
            ((u32)g_sample[i + 1] << 16) |
            ((u32)g_sample[i + 2] << 8) |
            ((u32)g_sample[i + 3]);
        if (v == 0u) continue;
        d = first_digit_u32(v);
        if (d >= 1 && d <= 9) {
            counts[d]++;
            total++;
        }
    }
    if (total == 0u) return 0.0;

    chi = 0.0;
    for (i = 1; i <= 9; i++) {
        double expected_freq;
        double expected_count;
        double observed;
        expected_freq = log10(1.0 + (1.0 / (double)i));
        expected_count = expected_freq * (double)total;
        observed = (double)counts[i];
        if (expected_count > 0.0) {
            double diff;
            diff = observed - expected_count;
            chi += (diff * diff) / expected_count;
        }
    }
    return clamp01(1.0 - clamp01(chi / (double)total));
}

static int cmp_u32_desc(const void *left, const void *right) {
    const u32 *a;
    const u32 *b;
    a = (const u32 *)left;
    b = (const u32 *)right;
    if (*a < *b) return 1;
    if (*a > *b) return -1;
    return 0;
}

static double zipf_alpha_counts(void) {
    u32 freqs[256];
    int n;
    int i;
    double sumx;
    double sumy;
    double sumxx;
    double sumxy;
    double den;
    double slope;

    n = 0;
    for (i = 0; i < 256; i++) {
        if (g_byte_counts[i] > 0u) {
            freqs[n++] = g_byte_counts[i];
        }
    }
    if (n < 3) return 0.0;

    qsort(freqs, (size_t)n, sizeof(freqs[0]), cmp_u32_desc);

    sumx = 0.0;
    sumy = 0.0;
    sumxx = 0.0;
    sumxy = 0.0;
    for (i = 0; i < n; i++) {
        double x;
        double y;
        x = log((double)(i + 1));
        y = log((double)freqs[i]);
        sumx += x;
        sumy += y;
        sumxx += x * x;
        sumxy += x * y;
    }

    den = ((double)n * sumxx) - (sumx * sumx);
    if (fabs(den) < 1e-12) return 0.0;
    slope = (((double)n * sumxy) - (sumx * sumy)) / den;
    if (-slope < 0.0) return 0.0;
    return -slope;
}

static int compute_entropy_blocks(double *out_blocks, int max_blocks, int block_size) {
    u32 offset;
    int idx;

    if (!out_blocks || max_blocks <= 0 || block_size <= 0) return 0;
    if (g_sample_len == 0) return 0;

    idx = 0;
    offset = 0u;
    while (offset < g_sample_len && idx < max_blocks) {
        u32 remain;
        u32 len;
        remain = g_sample_len - offset;
        len = remain < (u32)block_size ? remain : (u32)block_size;
        out_blocks[idx++] = entropy_of_buffer(g_sample + offset, len);
        offset += len;
    }
    return idx;
}

static double katz_dimension(const double *values, int count) {
    int i;
    double curve_length;
    double diameter;
    double base;
    double den;
    double fd;

    if (!values || count < 2) return 1.0;

    curve_length = 0.0;
    for (i = 1; i < count; i++) {
        double dy;
        dy = values[i] - values[i - 1];
        curve_length += sqrt(1.0 + (dy * dy));
    }
    if (curve_length <= 0.0) return 1.0;

    base = values[0];
    diameter = 0.0;
    for (i = 0; i < count; i++) {
        double dist;
        double dy;
        dy = values[i] - base;
        dist = sqrt((double)(i * i) + (dy * dy));
        if (dist > diameter) diameter = dist;
    }
    if (diameter <= 0.0) return 1.0;

    den = log10(diameter / curve_length) + log10((double)count);
    if (fabs(den) < 1e-9) return 1.0;
    fd = log10((double)count) / den;
    return clampd(fd, 1.0, 2.5);
}

static int perm_id3(int a, int b, int c) {
    if (a == 0 && b == 1 && c == 2) return 0;
    if (a == 0 && b == 2 && c == 1) return 1;
    if (a == 1 && b == 0 && c == 2) return 2;
    if (a == 1 && b == 2 && c == 0) return 3;
    if (a == 2 && b == 0 && c == 1) return 4;
    if (a == 2 && b == 1 && c == 0) return 5;
    return 0;
}

static double permutation_entropy_order3(void) {
    u32 counts[6];
    u32 total;
    u32 i;

    memset(counts, 0, sizeof(counts));
    total = 0u;

    if (g_sample_len < 3) return 0.5;

    for (i = 0; i + 2 < g_sample_len && i < 4096u; i++) {
        u8 w0;
        u8 w1;
        u8 w2;
        int idx[3];
        int pass;
        int j;
        int id;

        w0 = g_sample[i + 0];
        w1 = g_sample[i + 1];
        w2 = g_sample[i + 2];

        idx[0] = 0;
        idx[1] = 1;
        idx[2] = 2;

        for (pass = 0; pass < 2; pass++) {
            for (j = 0; j < 2 - pass; j++) {
                int ia;
                int ib;
                u8 va;
                u8 vb;
                ia = idx[j];
                ib = idx[j + 1];
                va = (ia == 0) ? w0 : (ia == 1 ? w1 : w2);
                vb = (ib == 0) ? w0 : (ib == 1 ? w1 : w2);
                if (vb < va || (vb == va && ib < ia)) {
                    int tmp;
                    tmp = idx[j];
                    idx[j] = idx[j + 1];
                    idx[j + 1] = tmp;
                }
            }
        }

        id = perm_id3(idx[0], idx[1], idx[2]);
        counts[id]++;
        total++;
    }

    if (total == 0u) return 0.5;

    {
        int k;
        double h;
        double max_h;
        h = 0.0;
        for (k = 0; k < 6; k++) {
            if (counts[k] > 0u) {
                double p;
                p = (double)counts[k] / (double)total;
                h -= p * log2_compat(p);
            }
        }
        max_h = log2_compat(6.0);
        if (max_h <= 0.0) return 0.5;
        return clamp01(1.0 - (h / max_h));
    }
}

static double gradient_coherence(const double *entropy_blocks, int block_count) {
    int i;
    double mean_diff;

    if (!entropy_blocks || block_count < 2) return 1.0;

    mean_diff = 0.0;
    for (i = 1; i < block_count; i++) {
        mean_diff += fabs(entropy_blocks[i] - entropy_blocks[i - 1]);
    }
    mean_diff /= (double)(block_count - 1);
    return clamp01(1.0 - (mean_diff / 8.0));
}

static double noether_consistency(const double *entropy_blocks, int block_count, double delta_ratio) {
    int seen[256];
    int unique;
    u32 limit;
    u32 i;
    double periodicity_proxy;
    double entropy_delta;

    if (g_sample_len == 0) return 0.0;

    memset(seen, 0, sizeof(seen));
    unique = 0;
    limit = g_sample_len < 512u ? g_sample_len : 512u;
    for (i = 0; i < limit; i++) {
        int b;
        b = (int)g_sample[i];
        if (!seen[b]) {
            seen[b] = 1;
            unique++;
        }
    }
    periodicity_proxy = (double)unique / 256.0;

    entropy_delta = 0.0;
    if (block_count >= 2) {
        entropy_delta = fabs(entropy_blocks[block_count - 1] - entropy_blocks[0]) / 8.0;
    }

    return clamp01(
        (0.40 * periodicity_proxy) +
        (0.30 * (1.0 - clamp01(entropy_delta))) +
        (0.30 * (1.0 - clamp01(delta_ratio)))
    );
}

static void compute_metrics(ProbeMetrics *out) {
    double blocks[MAX_ENTROPY_BLOCKS];
    int block_count;

    if (!out) return;
    memset(out, 0, sizeof(*out));

    out->entropy_shannon = shannon_entropy_counts();
    out->entropy_boltzmann = boltzmann_entropy_counts();
    out->symmetry = symmetry_score_counts();
    out->periodicity = lag_periodicity_score();
    out->zipf_alpha = zipf_alpha_counts();
    out->benford_score = benford_score_sample();
    out->perm_entropy = permutation_entropy_order3();
    out->xor_delta_ratio = clamp01(xor_delta_ratio());

    block_count = compute_entropy_blocks(blocks, MAX_ENTROPY_BLOCKS, ENTROPY_BLOCK_SIZE);
    out->katz_dimension = katz_dimension(blocks, block_count);
    out->gradient_coherence = gradient_coherence(blocks, block_count);
    out->noether_consistency = noether_consistency(blocks, block_count, out->xor_delta_ratio);

    out->h_lambda = clampd(
        out->entropy_shannon * out->xor_delta_ratio * (1.0 - out->symmetry + 0.1),
        0.0,
        8.0
    );
}

typedef struct {
    u32 dwLength;
    u32 dwMemoryLoad;
    u32 dwTotalPhys;
    u32 dwAvailPhys;
    u32 dwTotalPageFile;
    u32 dwAvailPageFile;
    u32 dwTotalVirtual;
    u32 dwAvailVirtual;
} MEMORYSTATUS_LEGACY;

static int check_ram(u32 *out_free_kb, u32 *out_load_pct) {
    MEMORYSTATUS_LEGACY ms;
    memset(&ms, 0, sizeof(ms));
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatus((LPMEMORYSTATUS)&ms);
    *out_free_kb = ms.dwAvailPhys / 1024u;
    *out_load_pct = ms.dwMemoryLoad;
    return (*out_free_kb >= (u32)RAM_MIN_FREE_KB && ms.dwMemoryLoad <= 90u);
}

static int compress_benchmark(int *out_ratio_pct) {
    static u8 buf_in[TEST_BUF_KB * 1024];
    static u8 buf_out[TEST_BUF_KB * 1024];
    int n;
    int i;
    u32 nonzero;
    clock_t t0;
    clock_t t1;

    n = TEST_BUF_KB * 1024;
    nonzero = 0u;

    srand(0x4145);
    for (i = 0; i < n; i++) {
        u8 base;
        u8 noise;
        base = (u8)(i % 16);
        noise = (rand() % 4 == 0) ? (u8)(rand() & 0x0F) : 0u;
        buf_in[i] = (u8)(base ^ noise);
    }

    t0 = clock();
    buf_out[0] = buf_in[0];
    for (i = 1; i < n; i++) {
        buf_out[i] = (u8)(buf_in[i] ^ buf_in[i - 1]);
    }
    t1 = clock();

    for (i = 0; i < n; i++) {
        if (buf_out[i] != 0u) nonzero++;
    }

    *out_ratio_pct = (int)((nonzero * 100u) / (u32)n);

    {
        double elapsed;
        elapsed = (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
        if (elapsed > 2.0) {
            printf("[PROBE] compression loop too slow: %.2f s\n", elapsed);
            return 0;
        }
    }

    return (*out_ratio_pct < COMPRESS_TARGET_RATIO);
}

static int inject_vault_seed(void) {
    FILE *f;
    int i;
    ensure_base_dirs();

    f = fopen(PATH_VAULT_SEED, "wb");
    if (!f) return 0;

    for (i = 0; i < 8192; i++) {
        u8 b;
        b = (u8)(((i * 131) + (i / 7) + 0x5A) & 0xFF);
        fwrite(&b, 1, 1, f);
    }
    fclose(f);
    return 1;
}

static int ask_yes_no_default_yes(const char *question) {
    char line[32];
    printf("%s [Y/n]: ", question);
    fflush(stdout);
    memset(line, 0, sizeof(line));
    if (!fgets(line, sizeof(line), stdin)) {
        return 1;
    }
    if (line[0] == 'n' || line[0] == 'N') return 0;
    return 1;
}

static void write_conversion_request(int requested) {
    FILE *f;
    char ts[32];
    iso_timestamp(ts, sizeof(ts));

    ensure_base_dirs();
    f = fopen(PATH_CONVERT_REQ, "wb");
    if (!f) return;

    fprintf(
        f,
        "{\n"
        "  \"schema\": \"aether.conversion.request.v1\",\n"
        "  \"requested\": %s,\n"
        "  \"source\": \"vault_probe.c\",\n"
        "  \"timestamp\": \"%s\"\n"
        "}\n",
        requested ? "true" : "false",
        ts
    );
    fclose(f);
}

/* ---------------------------------------------------------------------------
 * Linux-Fallback: Distro-Empfehlung anhand des freien RAMs zum Scanzeitpunkt.
 *
 * Tier-Tabelle nach linux_fallback (gleiche Metriken, neues OS-Profil):
 *   LinuxLegacy  (Kernel < 4.0): LocalOnly(0) / LanBeacon(1) / LanP2P(2)
 *                                  yggdrasil=nein  (alter TUN/veth, kein WG)
 *   LinuxModern  (Kernel >= 4.0): LanP2P(2) bis FullDht(4)
 *                                  yggdrasil=ja   (TUN/WireGuard korrekt)
 *
 *   free_kb < 131072  (< 128 MB frei)  -> antiX 23.1 i386
 *   free_kb < 524288  (< 512 MB frei)  -> MX Linux 21 i386
 *   free_kb >= 524288 (>= 512 MB frei) -> Debian 12 (bookworm) minimal
 * ---------------------------------------------------------------------------
 */
static const char *select_linux_distro(u32 free_kb) {
    if (free_kb < 131072u) return "antiX 23.1 i386";    /* < 128 MB frei */
    if (free_kb < 524288u) return "MX Linux 21 i386";   /* < 512 MB frei */
    return "Debian 12 (bookworm) minimal";              /* >= 512 MB frei */
}

static double compute_invariant_strength(const ProbeMetrics *m) {
    if (!m) return 0.0;
    return clamp01(
        (m->periodicity + m->benford_score + (1.0 - m->xor_delta_ratio) + m->symmetry) / 4.0
    );
}

static double compute_sce_score(const ProbeMetrics *m) {
    if (!m) return 0.0;
    return clamp01(
        (0.4 * m->symmetry) +
        (0.3 * m->benford_score) +
        (0.3 * m->gradient_coherence)
    );
}

static double compute_trust_score(const ProbeMetrics *m, double sce_score) {
    double entropy_term;
    double zipf_term;
    double katz_term;
    double delta_term;

    if (!m) return 0.0;

    entropy_term = clamp01(1.0 - (m->entropy_shannon / 8.0));
    zipf_term = clamp01(1.0 - (fabs(m->zipf_alpha - 1.0) / 2.0));
    katz_term = clamp01(1.0 - ((m->katz_dimension - 1.0) / 1.5));
    delta_term = clamp01(1.0 - m->xor_delta_ratio);

    return clamp01(
        (0.12 * entropy_term) +
        (0.08 * m->entropy_boltzmann) +
        (0.12 * m->symmetry) +
        (0.10 * m->benford_score) +
        (0.08 * m->perm_entropy) +
        (0.08 * zipf_term) +
        (0.08 * katz_term) +
        (0.10 * m->noether_consistency) +
        (0.12 * sce_score) +
        (0.12 * delta_term)
    );
}

static int metric_gate_passed(const ProbeMetrics *m, double sce_score, double trust_score) {
    if (!m) return 0;
    if (m->benford_score <= 0.35) return 0;
    if (m->katz_dimension >= 2.10) return 0;
    if (m->perm_entropy <= 0.20) return 0;
    if (m->h_lambda >= 5.50) return 0;
    if (sce_score <= 0.30) return 0;
    if (trust_score <= 0.30) return 0;
    return 1;
}

static void write_verdict(const ProbeVerdict *v) {
    FILE *f;
    char ts[32];

    if (!v) return;
    ensure_base_dirs();
    iso_timestamp(ts, sizeof(ts));

    f = fopen(PATH_VERDICT, "wb");
    if (!f) {
        fprintf(stderr, "[PROBE] cannot write verdict: %s\n", PATH_VERDICT);
        return;
    }

    fprintf(
        f,
        "{\n"
        "  \"schema\": \"aether.vault_probe.verdict.v2\",\n"
        "  \"vault_ready\": %s,\n"
        "  \"ram_ok\": %s,\n"
        "  \"compress_ok\": %s,\n"
        "  \"metric_ok\": %s,\n"
        "  \"strong_patterns\": %d,\n"
        "  \"vault_threshold\": %d,\n"
        "  \"files_scanned\": %d,\n"
        "  \"free_ram_kb\": %lu,\n"
        "  \"mem_load_pct\": %lu,\n"
        "  \"compress_ratio_pct\": %d,\n"
        "  \"compress_target_pct\": %d,\n"
        "  \"anchor_hits\": %d,\n"
        "  \"anchor_mask\": {\n"
        "    \"pi\": %s,\n"
        "    \"e\": %s,\n"
        "    \"pow2\": %s,\n"
        "    \"binmask\": %s,\n"
        "    \"threshold\": %s\n"
        "  },\n"
        "  \"metrics\": {\n"
        "    \"entropy\": %.12f,\n"
        "    \"boltzmann_entropy\": %.12f,\n"
        "    \"symmetry\": %.12f,\n"
        "    \"periodicity\": %.12f,\n"
        "    \"zipf_alpha\": %.12f,\n"
        "    \"benford_score\": %.12f,\n"
        "    \"katz_dimension\": %.12f,\n"
        "    \"perm_entropy\": %.12f,\n"
        "    \"xor_delta_ratio\": %.12f,\n"
        "    \"h_lambda\": %.12f,\n"
        "    \"noether_consistency\": %.12f,\n"
        "    \"gradient_coherence\": %.12f\n"
        "  },\n"
        "  \"sce_score\": %.12f,\n"
        "  \"trust_score\": %.12f,\n"
        "  \"invariant_strength\": %.12f,\n"
        "  \"injected_seed\": %s,\n"
        "  \"conversion_requested\": %d,\n"
        "  \"retry_after_sec\": %ld,\n"
        "  \"action\": \"%s\",\n"
        "  \"yggdrasil_recommended\": %s,\n"
        "  \"recommended_linux_distro\": \"%s\",\n"
        "  \"timestamp\": \"%s\"\n"
        "}\n",
        v->vault_ready ? "true" : "false",
        v->ram_ok ? "true" : "false",
        v->compress_ok ? "true" : "false",
        v->metric_ok ? "true" : "false",
        v->strong_patterns,
        VAULT_PATTERN_THRESHOLD,
        v->files_scanned,
        (unsigned long)v->free_kb,
        (unsigned long)v->mem_load_pct,
        v->compress_ratio_pct,
        COMPRESS_TARGET_RATIO,
        v->anchor_hits,
        (v->anchor_mask & AM_PI) ? "true" : "false",
        (v->anchor_mask & AM_E) ? "true" : "false",
        (v->anchor_mask & AM_POW2) ? "true" : "false",
        (v->anchor_mask & AM_BINMASK) ? "true" : "false",
        (v->anchor_mask & AM_THRESH) ? "true" : "false",
        v->metrics.entropy_shannon,
        v->metrics.entropy_boltzmann,
        v->metrics.symmetry,
        v->metrics.periodicity,
        v->metrics.zipf_alpha,
        v->metrics.benford_score,
        v->metrics.katz_dimension,
        v->metrics.perm_entropy,
        v->metrics.xor_delta_ratio,
        v->metrics.h_lambda,
        v->metrics.noether_consistency,
        v->metrics.gradient_coherence,
        v->sce_score,
        v->trust_score,
        v->invariant_strength,
        v->injected_seed ? "true" : "false",
        v->conversion_requested,
        v->retry_after_sec,
        v->action ? v->action : "unknown",
        v->yggdrasil_recommended ? "true" : "false",
        v->recommended_linux_distro ? v->recommended_linux_distro : "",
        ts
    );

    fclose(f);
    printf("[PROBE] verdict written: %s (action=%s)\n", PATH_VERDICT, v->action ? v->action : "unknown");
}

int main(int argc, char *argv[]) {
    ProbeVerdict verdict;
    long now;
    long remaining;

    (void)argc;
    (void)argv;

    memset(&verdict, 0, sizeof(verdict));
    verdict.action = "unknown";
    verdict.conversion_requested = -1;

    ensure_base_dirs();

    now = now_epoch_seconds();
    remaining = 0L;
    if (retry_window_active(now, &remaining)) {
        verdict.action = "waiting_retry_window";
        verdict.retry_after_sec = remaining;
        write_verdict(&verdict);
        printf("[PROBE] retry lock active: wait %ld sec (~%.2f h).\n", remaining, (double)remaining / 3600.0);
        return 2;
    }

    printf("[PROBE] Aether Legacy Probe (AE/AELab core metrics)\n");

    reset_scan_state();
    verdict.files_scanned = scan_vault_dir(PATH_VAULT_DIR);
    verdict.strong_patterns = count_strong_patterns();
    verdict.anchor_mask = g_anchor_mask;
    verdict.anchor_hits = g_anchor_hits;
    verdict.vault_ready = (verdict.strong_patterns >= VAULT_PATTERN_THRESHOLD) ? 1 : 0;

    compute_metrics(&verdict.metrics);

    verdict.ram_ok = check_ram(&verdict.free_kb, &verdict.mem_load_pct);
    verdict.compress_ok = compress_benchmark(&verdict.compress_ratio_pct);

    verdict.sce_score = compute_sce_score(&verdict.metrics);
    verdict.trust_score = compute_trust_score(&verdict.metrics, verdict.sce_score);
    verdict.invariant_strength = compute_invariant_strength(&verdict.metrics);
    verdict.metric_ok = metric_gate_passed(&verdict.metrics, verdict.sce_score, verdict.trust_score);

    printf("[PROBE] files=%d strong_patterns=%d vault_ready=%s\n",
           verdict.files_scanned,
           verdict.strong_patterns,
           verdict.vault_ready ? "yes" : "no");
    printf("[PROBE] ram_free_kb=%lu mem_load=%lu%% ram_ok=%s\n",
           (unsigned long)verdict.free_kb,
           (unsigned long)verdict.mem_load_pct,
           verdict.ram_ok ? "yes" : "no");
    printf("[PROBE] compress_ratio=%d%% target<%d%% compress_ok=%s\n",
           verdict.compress_ratio_pct,
           COMPRESS_TARGET_RATIO,
           verdict.compress_ok ? "yes" : "no");

    printf("[PROBE] entropy=%.4f boltz=%.4f sym=%.4f periodicity=%.4f zipf=%.4f benford=%.4f\n",
           verdict.metrics.entropy_shannon,
           verdict.metrics.entropy_boltzmann,
           verdict.metrics.symmetry,
           verdict.metrics.periodicity,
           verdict.metrics.zipf_alpha,
           verdict.metrics.benford_score);
    printf("[PROBE] katz=%.4f perm=%.4f xor_delta=%.4f h_lambda=%.4f noether=%.4f\n",
           verdict.metrics.katz_dimension,
           verdict.metrics.perm_entropy,
           verdict.metrics.xor_delta_ratio,
           verdict.metrics.h_lambda,
           verdict.metrics.noether_consistency);
    printf("[PROBE] sce=%.4f trust=%.4f invariant=%.4f metric_ok=%s\n",
           verdict.sce_score,
           verdict.trust_score,
           verdict.invariant_strength,
           verdict.metric_ok ? "yes" : "no");

    if (verdict.vault_ready && verdict.ram_ok && verdict.compress_ok && verdict.metric_ok) {
        int convert;
        verdict.action = "linux_fallback";
        verdict.yggdrasil_recommended = 1; /* Linux path: Yggdrasil via distro package */
        verdict.recommended_linux_distro = select_linux_distro(verdict.free_kb);
        printf("[PROBE] recommended linux distro: %s\n", verdict.recommended_linux_distro);
        convert = ask_yes_no_default_yes(
            "Convert existing files to Aether formats before Linux installation?"
        );
        verdict.conversion_requested = convert ? 1 : 0;
        write_conversion_request(convert);
        printf("[PROBE] linux fallback recommended. conversion_requested=%d\n", verdict.conversion_requested);
        printf("[PROBE] next: run installer path after conversion pipeline finishes.\n");
    } else if (!verdict.vault_ready || !verdict.metric_ok) {
        verdict.action = "inject_and_retry";
        verdict.yggdrasil_recommended = 0; /* not ready yet, vault/metrics missing */
        verdict.injected_seed = inject_vault_seed();
        write_retry_lock(now_epoch_seconds());
        verdict.retry_after_sec = RETRY_SECONDS;
        printf("[PROBE] injected seed=%s, retry lock set for 24h.\n", verdict.injected_seed ? "yes" : "no");
    } else {
        /* local_only: vault+metrics ok but ram or compress gate failed.
         * Node stays on Windows. If RAM was sufficient, Yggdrasil (WinTun) is
         * still installable on XP SP3+ and should be set up now. */
        verdict.action = "local_only";
        verdict.yggdrasil_recommended = verdict.ram_ok; /* RAM ok -> WinTun can run */
        if (verdict.yggdrasil_recommended) {
            printf("[PROBE] local_only but RAM ok: Yggdrasil (WinTun) install recommended.\n");
        } else {
            printf("[PROBE] hardware/compression gate failed. stay local and retry later.\n");
        }
    }

    write_verdict(&verdict);
    return 0;
}
