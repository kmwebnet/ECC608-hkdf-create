TARGET = hkdfcreate
#CC=F:/SysGCC/imx8m/gcc-linaro-6.3.1-2017.02-i686-mingw32_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc.exe
#RM=F:/SysGCC/raspberry/bin/rm.exe
DEFS= \
-DATCAPRINTF \
-DATCA_HAL_I2C
INC= \
-Icryptoauthlib \
-Icryptoauthlib/lib
CFLAGS=-g -Wall $(INC) $(DEFS)

OBJS := $(patsubst %.c,%.o,$(wildcard *.c)) \
        $(patsubst %.c,%.o,$(wildcard cryptoauthlib/lib/*.c)) \
        $(patsubst %.c,%.o,$(wildcard cryptoauthlib/lib/atcacert/*.c)) \
        $(patsubst %.c,%.o,$(wildcard cryptoauthlib/lib/basic/*.c)) \
        $(patsubst %.c,%.o,$(wildcard cryptoauthlib/lib/crypto/*.c)) \
        $(patsubst %.c,%.o,$(wildcard cryptoauthlib/lib/crypto/hashes/*.c)) \
        $(patsubst %.c,%.o,$(wildcard cryptoauthlib/lib/host/*.c)) \
        $(patsubst %.c,%.o,$(wildcard cryptoauthlib/lib/hal/atca_hal.c)) \
        cryptoauthlib/lib/hal/atca_hal.o \
        cryptoauthlib/lib/hal/hal_linux_timer.o \
        cryptoauthlib/lib/hal/hal_linux_i2c_userspace.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	$(RM) -f $(OBJS)
	$(RM) -f $(TARGET)

