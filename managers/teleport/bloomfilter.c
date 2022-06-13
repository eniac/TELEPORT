#include <lego/printk.h>
#include <teleport/bloomfilter.h>
#include <teleport/murmurhash2.h>

inline static int test_bit_set_bit(unsigned char * buf,
        unsigned int x, int set_bit)
{
    unsigned int byte;
    unsigned char c;
    unsigned int mask;

    byte = x >> 3;
    c = buf[byte];        // expensive memory access
    mask = 1 << (x % 8);

    if (c & mask) {
        return 1;
    } else {
        if (set_bit) {
            buf[byte] = c | mask;
        }
        return 0;
    }
}


static int bloom_check_add(struct bloomfilter * bloom,
        const void * buffer, int len, int add)
{
    int hits;
    register unsigned int a, b, x, i;

    if (bloom->ready == 0) {
        printk("bloom at %p not initialized!\n", (void *)bloom);
        return -1;
    }

    hits = 0;
    a = murmurhash2(buffer, len, 0x9747b28c);
    b = murmurhash2(buffer, len, a);

    for (i = 0; i < bloom->hashes; i++) {
        x = (a + i*b) % bloom->bits;
        if (test_bit_set_bit(bloom->bf, x, add)) {
            hits++;
        } else if (!add) {
            // Don't care about the presence of all the bits. Just our own.
            return 0;
        }
    }

    if (hits == bloom->hashes) {
        return 1;                // 1 == element already in (or collision)
    }

    return 0;
}

int bloom_init(struct bloomfilter * bloom, int entries, void* buf)
{
    char* xs;
    int count;
    // int num;

    bloom->ready = 0;

    bloom->entries = entries;
    bloom->bpe = 14;
    bloom->bits = entries * bloom->bpe;

    if (bloom->bits % 8) {
        bloom->bytes = (bloom->bits / 8) + 1;
    } else {
        bloom->bytes = bloom->bits / 8;
    }

    bloom->hashes = 9;

    bloom->bf = (unsigned char*)buf;
    if (bloom->bf == 0) {                                   // LCOV_EXCL_START
        return 1;
    }                                                          // LCOV_EXCL_STOP
    // Initialize
    xs = (void*)bloom->bf;
    count = bloom->bytes;
    while (count--)
        *xs++ = 0;

    bloom->ready = 1;
    return 0;
}


int bloom_check(struct bloomfilter * bloom, const void * buffer, int len)
{
    return bloom_check_add(bloom, buffer, len, 0);
}


int bloom_add(struct bloomfilter * bloom, const void * buffer, int len)
{
    return bloom_check_add(bloom, buffer, len, 1);
}

void bloom_free(struct bloomfilter * bloom)
{
    bloom->ready = 0;
}


int bloom_reset(struct bloomfilter * bloom)
{
    char* xs;
    int count;

    if (!bloom->ready) return 1;
    xs = (void*)bloom->bf;
    count = bloom->bytes;
    while (count--)
        *xs++ = 0;
    return 0;
}
