#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>

#define WHINE(a,...) fprintf(stderr, "%s:" a "\n", exec_name, ## __VA_ARGS__)
#define ABORT(msg,...)	do { \
	WHINE(msg, ## __VA_ARGS__); \
	exit(EXIT_FAILURE); \
} while (0)
#define BUG(msg,...)            ABORT("fatal:BUG:" msg, ## __VA_ARGS__)
#define FATAL(msg,...)            ABORT("fatal:" msg, ## __VA_ARGS__)
const char *exec_name;

void
usage() {
	printf("Usage:\n"
	       "    dpad [-h]\n"
	       "        Print this help.\n"
	       "\n"
	       "    dpad -e <out-file> <password> <secret> [password secret ...]\n"
	       "        Encrypt secrets with the corresponding passwords, write to <out-file>.\n"
	       "\n"
	       "    dpad -d <in-file> <password>\n"
	       "        Decrypt the secret from <in-file> with the <password>.\n");
}

// now assume max 32 secrets, and both secrets and passwords are NUL termiated char strings.
#define MAX_SEC_CNT 32

// prefix pag at most 2^10 - 1 bytes
#define MAX_PREFIX_PAD_BITS 8
#define PREFIX_PAD_MASK ((1ULL << MAX_PREFIX_PAD_BITS) - 1)

// large enough for enc/dec body
#define MAX_BUFFER_SIZE (1024 * 1024)

const char *sec[MAX_SEC_CNT];
const char *pwd[MAX_SEC_CNT];
size_t sec_cnt = 0;

unsigned char encrypted_header[randombytes_SEEDBYTES];
unsigned char body[MAX_BUFFER_SIZE];
size_t body_size = 2 * (1 << MAX_PREFIX_PAD_BITS);

static const unsigned char HASHKEY[] = "dpad";

int
enc()
{
	unsigned char pwd_mask[MAX_SEC_CNT][randombytes_SEEDBYTES];
	unsigned char header[MAX_SEC_CNT][randombytes_SEEDBYTES];
	int valid = 0;
	unsigned short start[MAX_SEC_CNT];
	unsigned char hbyte[MAX_SEC_CNT];
	size_t end[MAX_SEC_CNT], max_end = 0;

	assert(randombytes_SEEDBYTES <= crypto_generichash_BYTES_MAX);

	for (int i = 0; i < sec_cnt; ++i) {
		unsigned char hash[crypto_generichash_BYTES_MAX];
		assert(2 + sizeof header[i] <= sizeof hash);
		crypto_generichash(hash, sizeof hash, (const unsigned char*)pwd[i], strlen(pwd[i]), HASHKEY, sizeof HASHKEY);
		randombytes_buf_deterministic(pwd_mask[i], sizeof pwd_mask[i], hash);
		hbyte[i] = hash[randombytes_SEEDBYTES];
	}

	// allocation
	while (!valid) {
		randombytes_buf(encrypted_header, sizeof(encrypted_header));

		int found_intersect = 0;
		max_end = 0;
		for (int i = 0; i < sec_cnt; ++i) {
			for (int j = 0; j < sizeof header[i]; ++j) {
				header[i][j] = encrypted_header[j] ^ pwd_mask[i][j];
			}

			// assume LE byte endian
			start[i] = (*(unsigned short *)header[i]) & (unsigned short)PREFIX_PAD_MASK;
			header[i][0] ^= hbyte[i]; // reinforce entropy
			end[i] = (size_t)start[i] + sizeof(unsigned short) + strlen(sec[i]);

			for (int j = 0; j < i; ++j) {
				if (! (end[j] <= (size_t)start[i] || end[i] <= (size_t)start[j]) ) {
					found_intersect = 1;
					break;
				}
			}
			if (found_intersect) break;
			if (max_end < end[i]) max_end = end[i];
		}

		if (!found_intersect) {
			valid = 1;
		}
	}

	// encrypt message
	randombytes_buf(body, sizeof body);
	for (int i = 0; i < sec_cnt; ++i) {
		unsigned char mask[sizeof body];
		const size_t l = end[i] - start[i] - sizeof(unsigned short);
		randombytes_buf_deterministic(mask, sizeof mask, header[i]);
		body[start[i]]     = mask[start[i]]     ^ (l & 0xff);
		body[start[i] + 1] = mask[start[i] + 1] ^ ((l >> 8) & 0xff);
		for (int j = start[i] + 2; j < end[i]; ++j) {
			body[j]    = mask[j]            ^ sec[i][j - start[i] - 2];
		}
	}

	return 0;
}

int
dec()
{
	unsigned char header[randombytes_SEEDBYTES];
	unsigned short start, length;
	unsigned char mask[sizeof body];
	unsigned char hash[crypto_generichash_BYTES_MAX];
	unsigned char hbyte;
	unsigned char *secret;

	assert(randombytes_SEEDBYTES <= crypto_generichash_BYTES_MAX);

	// decrypt header
	crypto_generichash(hash, sizeof hash, (const unsigned char*)pwd[0], strlen(pwd[0]), HASHKEY, sizeof HASHKEY);
	hbyte = hash[randombytes_SEEDBYTES];
	randombytes_buf_deterministic(header, sizeof(header), hash);
	for (int i = 0; i < sizeof header; ++i) {
		header[i] ^= encrypted_header[i];
	}
	start = (*(unsigned short *)header) & (unsigned short)PREFIX_PAD_MASK;
	header[0] ^= hbyte;

	randombytes_buf_deterministic(mask, body_size, header);
	for (int i = 0; i < body_size; ++i) {
		body[i] ^= mask[i];
	}
	secret = body + start;
	length = *(const unsigned short*)secret;
	secret += 2;
	secret[length] = 0; // assume secret are printable strings
	sec[0] = (const char *)secret;

	return 0;
}

int
main(const int argc, const char *const argv[])
{
	if (argc <= 1 || strcmp(argv[1], "-h") == 0) {
		usage();
		return 0;
	} else if (argc <= 3) {
		usage();
		return 1;
	}

	enum { ENC, DEC } mode;

	// parse options
	if (strcmp(argv[1], "-e") == 0) {
		mode = ENC;
	} else if (strcmp(argv[1], "-d") == 0) {
		mode = DEC;
	} else {
		usage();
		return 1;
	}
	const char *const filename = argv[2];
	if (0 == *filename) {
		usage();
		return 1;
	}

	switch (mode) {
		case ENC:
			if ((argc - 3) % 2 != 0) {
				usage();
				return 1;
			}
			sec_cnt = (argc - 3) / 2;
			if (sec_cnt > MAX_SEC_CNT) {
				usage();
				return 1;
			}
			for (int i = 0; i < sec_cnt; ++i) {
				pwd[i] = argv[3 + 2 * i + 0];
				sec[i] = argv[3 + 2 * i + 1];
				for (int j = 0; j < i; ++j) {
					if (strcmp(pwd[i], pwd[j]) == 0) {
						FATAL("all passwords must be distinct.");
					}
				}
			}
			break;
		case DEC:
			if (argc != 4) {
				usage();
				return 1;
			}
			pwd[0] = argv[3];
			break;
		default: BUG("invalid mode");
	}

	// init log
	exec_name = strrchr(argv[0], '/');
	if (!exec_name++) exec_name = argv[0];

	// init sodium
	if (sodium_init() == -1) FATAL("fail to init sodium");

	switch (mode) {
		case ENC:
			enc();

			{
				FILE *f = fopen(filename, "wb");
				fwrite(encrypted_header, sizeof(encrypted_header), 1, f);
				fwrite(body, body_size, 1, f);
				fclose(f);
				f = 0;
			}
			break;
		case DEC:
			{
				FILE *f = fopen(filename, "rb");
				fread(encrypted_header, sizeof(encrypted_header), 1, f);
				body_size = fread(body, 1, sizeof(body), f);
				fclose(f);
				f = 0;
			}

			dec();
			puts(sec[0]);

			break;
		default: BUG("invalid mode");
	}

	return 0;
}
