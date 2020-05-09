#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

#include "cryptoauthlib.h"
#include "hal/hal_linux_i2c_userspace.h"

#include "host/atca_host.h"
#include "configure.h"


void get_atecc608cfg(ATCAIfaceCfg *cfg)
{
//	config for Jetson Nano
		cfg->iface_type             = ATCA_I2C_IFACE;
                cfg->devtype                = ATECC608A;
                cfg->atcai2c.slave_address  = 0XC0;
                cfg->atcai2c.bus            = 1;
                cfg->atcai2c.baud           = 1000000;
                cfg->wake_delay             = 1500;
                cfg->rx_retries             = 20;

return;
}

int main(int argc, char *argv[])
{



    if (argc < 2)
    {
        fputs("need target file name:",stderr );
        exit(1);
    }

    ATCAIfaceCfg cfg;

    get_atecc608cfg(&cfg);

    ATCA_STATUS status = atcab_init(&cfg);
	
    if (status != ATCA_SUCCESS) {
        fprintf(stderr, "atcab_init() failed with ret=0x%08d\n", status);
        exit(1);
    }
	

    status = atca_configure(0xc0, &cfg);
    if (status != ATCA_SUCCESS) {
        fprintf(stderr, "atca_configure failed with ret=0x%08d\n", status);
        exit(1);
    }

uint8_t encryptkey[] = {
    0x77 , 0x72 , 0x69 , 0x74 , 0x69 , 0x6e , 0x67 , 0x20 , 0x70 , 0x75 , 0x62 , 0x20 , 0x6b , 0x65 , 0x79 , 0x20 , 
    0x62 , 0x79 , 0x20 , 0x75 , 0x73 , 0x69 , 0x6e , 0x67 , 0x20 , 0x65 , 0x6e , 0x63 , 0x72 , 0x79 , 0x70 , 0x74 ,
    };


    if (ATCA_SUCCESS != (status = atcab_write_zone(ATCA_ZONE_DATA, 6,  0, 0,  encryptkey, ATCA_KEY_SIZE)))
    {
        fprintf(stderr, "writing IO Protection Key by using atcab_write_zone() on slot 6 failed: %x\r\n", status);
        exit(1);
    }
    

    atcab_release();
    status = atcab_init(&cfg);
	
    if (status != ATCA_SUCCESS) {
        fprintf(stderr, "atcab_init() failed with ret=0x%08d\n", status);
        exit(1);
    }


//atcab_kdf 
    uint8_t out_nonce[32];
    uint8_t out_kdf_hkdf_encrypted[32];
    atca_io_decrypt_in_out_t io_dec_params;
    uint8_t data_input_32[32]; 
    uint8_t nonce[32];
    uint8_t digest[32];
    uint8_t pubkey[64];
    uint8_t signature[64];

    uint8_t outkeybuf[192];

    FILE *fp1;

    atcab_random(data_input_32);
    atcab_random(nonce);

    if (ATCA_SUCCESS != (status = atcab_nonce(nonce)))
    {
        printf("atcab_nonce(nonce) failed: %x\r\n", status);
    }


    if (ATCA_SUCCESS != (status = atcab_kdf(
        KDF_MODE_ALG_HKDF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT_ENC, 
        0x1234,  
        KDF_DETAILS_HKDF_MSG_LOC_INPUT | ((uint32_t)sizeof(data_input_32) << 24), 
        data_input_32, out_kdf_hkdf_encrypted , out_nonce)))

    {
        printf("atcab_kdf_enc failed: %x\r\n", status);
    }


    // Decrypt the KDF result
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = encryptkey;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = out_kdf_hkdf_encrypted;
    io_dec_params.data_size = 32;
    status = atcah_io_decrypt(&io_dec_params);

    // write to stdout
    fwrite(out_kdf_hkdf_encrypted , sizeof(uint8_t) , 32, stdout);
    fflush(stdout);
    //build key file

    memcpy(outkeybuf, data_input_32 , 32);
    memcpy(&outkeybuf[32], nonce , 32);

    uint8_t serial[ATCA_SERIAL_NUM_SIZE];
    status = atcab_read_serial_number(serial);
    if (status != ATCA_SUCCESS) {
    	fprintf(stderr, "atcab_read_serial_number() failed with ret=0x%08d/r/n", status);
        exit(1);
    }


    status = atcab_genkey(1 , pubkey);
    if (status != ATCA_SUCCESS) {
    	fprintf(stderr, "atcab_genkey(1) failed with ret=0x%08d/r/n", status);
        exit(1);
    }

    memcpy(&outkeybuf[64], pubkey, 64);

    status = atcab_sha_start();
    if (status != ATCA_SUCCESS) {
    	fprintf(stderr, "atcab_sha_start() failed with ret=0x%08d/r/n", status);
        exit(1);
    }

    status = atcab_sha_update(outkeybuf);
    if (status != ATCA_SUCCESS) {
    	fprintf(stderr, "atcab_sha_update() failed with ret=0x%08d/r/n", status);
        exit(1);
    }

    status = atcab_sha_update(&outkeybuf[64]);
    if (status != ATCA_SUCCESS) {
    	fprintf(stderr, "atcab_sha_update() failed with ret=0x%08d/r/n", status);
        exit(1);
    }


    status = atcab_sha_end(digest, ATCA_SERIAL_NUM_SIZE, serial);
    if (status != ATCA_SUCCESS) {
    	fprintf(stderr, "atcab_sha_end() failed with ret=0x%08d/r/n", status);
        exit(1);
    }



    status = atcab_sign(1 , digest, signature);
    if (status != ATCA_SUCCESS) {
    	fprintf(stderr, "atcab_sign() failed with ret=0x%08d/r/n", status);
        exit(1);
    }

    memcpy(&outkeybuf[128], signature, 64);

    if ((fp1 = fopen(argv[1], "wb")) == NULL)
    {
        fprintf(stderr, "Can not open ¥'%s¥'.¥n", argv[1]);
        exit(1);
    }

    if (fwrite(outkeybuf , sizeof(uint8_t) , 192 , fp1) != 192)
    {
        fprintf(stderr, "Can not write ¥'%s¥'.¥n", argv[1]);
        fclose(fp1);
        exit(1);
    }

	atcab_release();

    return (0);
}
