#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <gcrypt.h>
#include "util.h"
#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"


struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];

const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

void generate_publickey_and_address(struct Point *publickey,bool compress,char *dst_publickey,char *dst_address);
/*
for some reason the GMP function mp_set_memory_functions needs a extra parameter in the function call of realloc  and free warppers
*/
void *wrapper_gcry_alloc(size_t size);
void *wrapper_gcry_realloc(void *ptr, size_t old_size,  size_t new_size); 
void wrapper_gcry_free(void *ptr, size_t cur_size);

void calculate_from_key(unsigned long long int num, char *str_address) {
    char hex_str[17];
    snprintf(hex_str, sizeof(hex_str), "%016llx", num);

    mpz_t key;
    struct Point publickey;
    char str_publickey[131];

    mpz_init_set_str(EC.p, EC_constant_P, 16);
    mpz_init_set_str(EC.n, EC_constant_N, 16);
    mpz_init_set_str(G.x, EC_constant_Gx, 16);
    mpz_init_set_str(G.y, EC_constant_Gy, 16);
    init_doublingG(&G);

    mpz_init(publickey.x);
    mpz_init(publickey.y);
    mpz_init(key);

    mpz_set_str(key, hex_str, 16);
    mpz_mod(key, key, EC.n);
    Scalar_Multiplication(G, &publickey, key);

    gmp_printf("privatekey: %0.64Zx\n", key);

    generate_publickey_and_address(&publickey, true, str_publickey, str_address);
}

void generate_random_number_01(unsigned long long* random_num) {
    unsigned long long min = 0x200000000000000;
    unsigned long long max = 0x20fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}

void generate_random_number_02(unsigned long long* random_num) {
    unsigned long long min = 0x210000000000000;
    unsigned long long max = 0x21fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_03(unsigned long long* random_num) {
    unsigned long long min = 0x220000000000000;
    unsigned long long max = 0x22fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_04(unsigned long long* random_num) {
    unsigned long long min = 0x230000000000000;
    unsigned long long max = 0x23fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_05(unsigned long long* random_num) {
    unsigned long long min = 0x240000000000000;
    unsigned long long max = 0x24fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_06(unsigned long long* random_num) {
    unsigned long long min = 0x250000000000000;
    unsigned long long max = 0x25fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_07(unsigned long long* random_num) {
    unsigned long long min = 0x260000000000000;
    unsigned long long max = 0x26fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_08(unsigned long long* random_num) {
    unsigned long long min = 0x270000000000000;
    unsigned long long max = 0x27fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_09(unsigned long long* random_num) {
    unsigned long long min = 0x280000000000000;
    unsigned long long max = 0x28fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_10(unsigned long long* random_num) {
    unsigned long long min = 0x290000000000000;
    unsigned long long max = 0x29fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_11(unsigned long long* random_num) {
    unsigned long long min = 0x2a0000000000000;
    unsigned long long max = 0x2afffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_12(unsigned long long* random_num) {
    unsigned long long min = 0x2b0000000000000;
    unsigned long long max = 0x2bfffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_13(unsigned long long* random_num) {
    unsigned long long min = 0x2c0000000000000;
    unsigned long long max = 0x2cfffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_14(unsigned long long* random_num) {
    unsigned long long min = 0x2d0000000000000;
    unsigned long long max = 0x2dfffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_15(unsigned long long* random_num) {
    unsigned long long min = 0x2e0000000000000;
    unsigned long long max = 0x2efffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_16(unsigned long long* random_num) {
    unsigned long long min = 0x2f0000000000000;
    unsigned long long max = 0x2ffffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_17(unsigned long long* random_num) {
    unsigned long long min = 0x300000000000000;
    unsigned long long max = 0x30fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_18(unsigned long long* random_num) {
    unsigned long long min = 0x310000000000000;
    unsigned long long max = 0x31fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_19(unsigned long long* random_num) {
    unsigned long long min = 0x320000000000000;
    unsigned long long max = 0x32fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_20(unsigned long long* random_num) {
    unsigned long long min = 0x330000000000000;
    unsigned long long max = 0x33fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_21(unsigned long long* random_num) {
    unsigned long long min = 0x340000000000000;
    unsigned long long max = 0x34fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_22(unsigned long long* random_num) {
    unsigned long long min = 0x350000000000000;
    unsigned long long max = 0x35fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_23(unsigned long long* random_num) {
    unsigned long long min = 0x360000000000000;
    unsigned long long max = 0x36fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_24(unsigned long long* random_num) {
    unsigned long long min = 0x370000000000000;
    unsigned long long max = 0x37fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_25(unsigned long long* random_num) {
    unsigned long long min = 0x380000000000000;
    unsigned long long max = 0x38fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_26(unsigned long long* random_num) {
    unsigned long long min = 0x390000000000000;
    unsigned long long max = 0x39fffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_27(unsigned long long* random_num) {
    unsigned long long min = 0x3a0000000000000;
    unsigned long long max = 0x3afffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_28(unsigned long long* random_num) {
    unsigned long long min = 0x3b0000000000000;
    unsigned long long max = 0x3bfffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_29(unsigned long long* random_num) {
    unsigned long long min = 0x3c0000000000000;
    unsigned long long max = 0x3cfffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_30(unsigned long long* random_num) {
    unsigned long long min = 0x3d0000000000000;
    unsigned long long max = 0x3dfffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_31(unsigned long long* random_num) {
    unsigned long long min = 0x3e0000000000000;
    unsigned long long max = 0x3efffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}
void generate_random_number_32(unsigned long long* random_num) {
    unsigned long long min = 0x3f0000000000000;
    unsigned long long max = 0x3ffffffffffffff;
    unsigned long long range = max - min + 1; // khoảng giá trị cần sinh ngẫu nhiên

    // Lấy giá trị thời gian hiện tại với độ chính xác nano giây
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // Sử dụng giá trị thời gian và nano giây để tạo giá trị seed cho bộ sinh số ngẫu nhiên
    unsigned long long seed = ts.tv_sec * 1000000000 + ts.tv_nsec;
    srand(seed);

    // Sinh số ngẫu nhiên trong phạm vi từ min đến max
    *random_num = ((unsigned long long) rand() << 32 | rand()) % range + min;
}



int main() {
    unsigned long long random_num;
    int func_num;

    srand(time(NULL)); // Khởi tạo seed cho hàm rand()
	func_num = rand() % 32 + 1; // Số ngẫu nhiên từ 1 đến 32

    // Lặp vô hạn
    while (1) {
        // Chọn ngẫu nhiên một hàm generate_random_number_xx để sử dụng
        
        switch (func_num) {
            case 1:
                generate_random_number_01(&random_num);
                break;
            case 2:
                generate_random_number_02(&random_num);
                break;
            case 3:
                generate_random_number_03(&random_num);
                break;
            case 4:
                generate_random_number_04(&random_num);
                break;
            case 5:
                generate_random_number_05(&random_num);
                break;
            case 6:
                generate_random_number_06(&random_num);
                break;
            case 7:
                generate_random_number_07(&random_num);
                break;
            case 8:
                generate_random_number_08(&random_num);
                break;
            case 9:
                generate_random_number_09(&random_num);
                break;
            case 10:
                generate_random_number_10(&random_num);
                break;
            case 11:
                generate_random_number_11(&random_num);
                break;
            case 12:
                generate_random_number_12(&random_num);
                break;
            case 13:
                generate_random_number_13(&random_num);
                break;
            case 14:
                generate_random_number_14(&random_num);
                break;
            case 15:
                generate_random_number_15(&random_num);
                break;
            case 16:
                generate_random_number_16(&random_num);
                break;
            case 17:
                generate_random_number_17(&random_num);
                break;
            case 18:
                generate_random_number_18(&random_num);
                break;
            case 19:
                generate_random_number_19(&random_num);
                break;
            case 20:
                generate_random_number_20(&random_num);
                break;
            case 21:
                generate_random_number_21(&random_num);
                break;
            case 22:
                generate_random_number_22(&random_num);
                break;
            case 23:
                generate_random_number_23(&random_num);
                break;				
		    case 24:
                generate_random_number_24(&random_num);
                break;
		    case 25:
                generate_random_number_25(&random_num);
                break;
		    case 26:
                generate_random_number_26(&random_num);
                break;
		    case 27:
                generate_random_number_27(&random_num);
                break;
		    case 28:
                generate_random_number_28(&random_num);
                break;
		    case 29:
                generate_random_number_29(&random_num);
                break;
		    case 30:
                generate_random_number_30(&random_num);
                break;
		    case 31:
                generate_random_number_31(&random_num);
                break;
		    case 32:
                generate_random_number_32(&random_num);
                break;
            default:
                break;
        }
        //printf(": %llx\n", random_num);
    mpz_t key;
    struct Point publickey;
    char str_publickey[131];
    char str_address[50];

    mp_set_memory_functions(wrapper_gcry_alloc, wrapper_gcry_realloc, wrapper_gcry_free);

    mpz_init_set_str(EC.p, EC_constant_P, 16);
    mpz_init_set_str(EC.n, EC_constant_N, 16);
    mpz_init_set_str(G.x, EC_constant_Gx, 16);
    mpz_init_set_str(G.y, EC_constant_Gy, 16);
    init_doublingG(&G);

    mpz_init(publickey.x);
    mpz_init(publickey.y);
    mpz_init(key);
	
	char hex_str[17];
    sprintf(hex_str, "%016llx", random_num);
    mpz_set_str(key, hex_str, 16);
    mpz_mod(key, key, EC.n);
    Scalar_Multiplication(G, &publickey, key);
    generate_publickey_and_address(&publickey, true, str_publickey, str_address);
	
	if (str_address[1] == '3') {//13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 
    //printf("%016llx: %s\n", random_num, str_address);
	if (str_address[2] == 'z') {//13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 
    //printf("%016llx: %s\n", random_num, str_address);
	if (str_address[3] == 'b') {//13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 
    printf("%016llx: %s\n", random_num, str_address);
	if (str_address[4] == '1') {//13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so 
    printf("%016llx: %s\n", random_num, str_address);
	
	
	}
	
	}
	
	}
	
    } else {
    //free(mp_set_memory_functions);
    }	
        
		
	/////
    }

    return 0;
}

void generate_publickey_and_address(struct Point *publickey,bool compress,char *dst_publickey,char *dst_address)	{
	char bin_publickey[65];
	char bin_sha256[32];
	char bin_digest[60];
	size_t pubaddress_size = 50;
	memset(dst_address,0,50);
	memset(dst_publickey,0,131);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (dst_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(dst_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(dst_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(dst_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(dst_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_digest+1);
	
	/* Firts byte 0, this is for the Address begining with 1.... */
	
	bin_digest[0] = 0;
	
	/* Double sha256 checksum */	
	sha256(bin_digest, 21, bin_digest+21);
	sha256(bin_digest+21, 32, bin_digest+21);
	
	/* Get the address */
	if(!b58enc(dst_address,&pubaddress_size,bin_digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}

void *wrapper_gcry_alloc(size_t size)	{	//To use calloc instead of malloc
	return gcry_calloc(size,1);
}

void *wrapper_gcry_realloc(void *ptr, size_t old_size,  size_t new_size)	{
	return gcry_realloc(ptr,new_size);
}

void wrapper_gcry_free(void *ptr, size_t cur_size)	{
	gcry_free(ptr);
}
