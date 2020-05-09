
#include "stdio.h"
#include "stdlib.h"

#include "cryptoauthlib.h"
#include "host/atca_host.h"

void print_public_key(uint8_t pubkey[ATCA_PUB_KEY_SIZE]);
int atca_configure(uint8_t i2c_addr, ATCAIfaceCfg *cfg);

