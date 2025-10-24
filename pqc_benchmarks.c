#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <oqs/oqs.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define ITERATIONS 20

typedef struct {
    unsigned long long user, nice, system, idle;
} cpu_times_t;

static void read_cpu_times(cpu_times_t *t) {
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) { memset(t, 0, sizeof(cpu_times_t)); return; }
    fscanf(fp, "cpu %llu %llu %llu %llu", &t->user, &t->nice, &t->system, &t->idle);
    fclose(fp);
}

static double cpu_usage_percent(cpu_times_t *start, cpu_times_t *end,
                                double wall_start, double wall_end) {
    unsigned long long s_total = start->user + start->nice + start->system + start->idle;
    unsigned long long e_total = end->user + end->nice + end->system + end->idle;
    unsigned long long total_diff = e_total - s_total;
    unsigned long long idle_diff  = end->idle - start->idle;

    // fallback to process-level CPU usage if total_diff == 0
    if (total_diff == 0) {
        struct rusage usage;
        getrusage(RUSAGE_SELF, &usage);
        double cpu_used = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec +
                          (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6;
        double elapsed = wall_end - wall_start;
        if (elapsed <= 0) return 0.0;
        double percent = (cpu_used / elapsed) * 100.0;
        return percent > 100.0 ? 100.0 : percent;
    }

    return 100.0 * (1.0 - ((double)idle_diff / (double)total_diff));
}

static double now() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static double get_memory_mb() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss / 1024.0; // MB
}

static void log_csv(FILE *fp, const char *alg, const char *op,
                    double avg, double cpu, double mem) {
    fprintf(fp, "%s,%s,%.3f,%.2f,%.2f\n", alg, op, avg, cpu, mem);
    fflush(fp);
}

/* =======================  BENCHMARK HELPERS  ========================= */

static void benchmark_kem(FILE *fp, const char *alg) {
    if (!OQS_KEM_alg_is_enabled(alg)) return;
    OQS_KEM *kem = OQS_KEM_new(alg);
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss1 = malloc(kem->length_shared_secret);
    uint8_t *ss2 = malloc(kem->length_shared_secret);

    const char *ops[] = {"KeyGen", "Encaps", "Decaps", NULL};
    for (int i = 0; ops[i]; i++) {
        double total = 0, mem = 0, cpu_sum = 0;
        for (int j = 0; j < ITERATIONS; j++) {
            cpu_times_t c1, c2;
            read_cpu_times(&c1);
            double t1 = now();

            if (strcmp(ops[i], "KeyGen") == 0)
                OQS_KEM_keypair(kem, pk, sk);
            else if (strcmp(ops[i], "Encaps") == 0)
                OQS_KEM_encaps(kem, ct, ss1, pk);
            else if (strcmp(ops[i], "Decaps") == 0)
                OQS_KEM_decaps(kem, ss2, ct, sk);

            double t2 = now();
            usleep(1000); // ensure measurable CPU tick
            read_cpu_times(&c2);
            double cpu = cpu_usage_percent(&c1, &c2, t1, t2);
            total += (t2 - t1) * 1000;
            mem += get_memory_mb();
            cpu_sum += cpu;
        }
        log_csv(fp, alg, ops[i], total / ITERATIONS, cpu_sum / ITERATIONS, mem / ITERATIONS);
    }

    OQS_KEM_free(kem);
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
}

static void benchmark_sig(FILE *fp, const char *alg) {
    if (!OQS_SIG_alg_is_enabled(alg)) return;
    OQS_SIG *sig = OQS_SIG_new(alg);
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t msg[32] = {0};
    uint8_t *signature = malloc(sig->length_signature);
    size_t siglen = 0;

    const char *ops[] = {"KeyGen", "Sign", "Verify", NULL};
    for (int i = 0; ops[i]; i++) {
        double total = 0, mem = 0, cpu_sum = 0;
        for (int j = 0; j < ITERATIONS; j++) {
            cpu_times_t c1, c2;
            read_cpu_times(&c1);
            double t1 = now();

            if (strcmp(ops[i], "KeyGen") == 0)
                OQS_SIG_keypair(sig, pk, sk);
            else if (strcmp(ops[i], "Sign") == 0)
                OQS_SIG_sign(sig, signature, &siglen, msg, sizeof(msg), sk);
            else if (strcmp(ops[i], "Verify") == 0)
                OQS_SIG_verify(sig, msg, sizeof(msg), signature, siglen, pk);

            double t2 = now();
            usleep(1000);
            read_cpu_times(&c2);
            double cpu = cpu_usage_percent(&c1, &c2, t1, t2);
            total += (t2 - t1) * 1000;
            mem += get_memory_mb();
            cpu_sum += cpu;
        }
        log_csv(fp, alg, ops[i], total / ITERATIONS, cpu_sum / ITERATIONS, mem / ITERATIONS);
    }

    OQS_SIG_free(sig);
    free(pk); free(sk); free(signature);
}

/* ===================  CLASSIC CRYPTO (RSA / ECC)  ==================== */

static void benchmark_rsa(FILE *fp, int bits) {
    char alg[32];
    sprintf(alg, "RSA-%d", bits);
    double total = 0, mem = 0, cpu_sum = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        cpu_times_t c1, c2;
        read_cpu_times(&c1);
        double t1 = now();

        BIGNUM *bn = BN_new();
        BN_set_word(bn, RSA_F4);
        RSA *rsa = RSA_new();
        RSA_generate_key_ex(rsa, bits, bn, NULL);

        double t2 = now();
        usleep(1000);
        read_cpu_times(&c2);
        double cpu = cpu_usage_percent(&c1, &c2, t1, t2);

        total += (t2 - t1) * 1000;
        mem += get_memory_mb();
        cpu_sum += cpu;

        RSA_free(rsa);
        BN_free(bn);
    }
    log_csv(fp, alg, "KeyGen", total / ITERATIONS, cpu_sum / ITERATIONS, mem / ITERATIONS);
}

static void benchmark_ecc(FILE *fp, int nid, const char *name) {
    double total = 0, mem = 0, cpu_sum = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        cpu_times_t c1, c2;
        read_cpu_times(&c1);
        double t1 = now();

        EC_KEY *ec = EC_KEY_new_by_curve_name(nid);
        EC_KEY_generate_key(ec);

        double t2 = now();
        usleep(1000);
        read_cpu_times(&c2);
        double cpu = cpu_usage_percent(&c1, &c2, t1, t2);

        total += (t2 - t1) * 1000;
        mem += get_memory_mb();
        cpu_sum += cpu;

        EC_KEY_free(ec);
    }
    log_csv(fp, name, "KeyGen", total / ITERATIONS, cpu_sum / ITERATIONS, mem / ITERATIONS);
}

/* =========================  MAIN  ============================ */

int main() {
    OQS_init();

    FILE *fkem = fopen("kem_report.csv", "w");
    FILE *fsig = fopen("sig_report.csv", "w");
    FILE *fclassic = fopen("classic_report.csv", "w");

    fprintf(fkem, "Algorithm,Operation,Time(ms),CPU(%%),Memory(MB)\n");
    fprintf(fsig, "Algorithm,Operation,Time(ms),CPU(%%),Memory(MB)\n");
    fprintf(fclassic, "Algorithm,Operation,Time(ms),CPU(%%),Memory(MB)\n");

    printf("Running IEEE-grade light PQC benchmark (20 iterations) ...\n");

    // PQC KEM
    benchmark_kem(fkem, OQS_KEM_alg_ml_kem_512);
    benchmark_kem(fkem, OQS_KEM_alg_ml_kem_768);
    benchmark_kem(fkem, OQS_KEM_alg_ml_kem_1024);

    // PQC SIG
    benchmark_sig(fsig, OQS_SIG_alg_ml_dsa_44);
    benchmark_sig(fsig, OQS_SIG_alg_ml_dsa_65);
    benchmark_sig(fsig, OQS_SIG_alg_ml_dsa_87);

    // Classic crypto
    benchmark_rsa(fclassic, 2048);
    benchmark_rsa(fclassic, 4096);
    benchmark_ecc(fclassic, NID_X9_62_prime256v1, "ECDSA-P256");
    benchmark_ecc(fclassic, NID_secp384r1, "ECDSA-P384");

    fclose(fkem);
    fclose(fsig);
    fclose(fclassic);
    OQS_destroy();

    printf("\n✅ Benchmark complete! Reports generated:\n");
    printf(" - kem_report.csv\n - sig_report.csv\n - classic_report.csv\n");
    return 0;
}
