# ECC608-hkdf-create

This configures ATECC608 secure chip from Jetson Nano and get a random 32byte key and signed HKDF master key corresponding to HKDF functionality.  

Due to chip's secure function, once if it has configured, you can't change config contents.

# Requirements

  install "apt install build-essential".  

# Environment reference
  
  Jetson Nano   
  this project initializes I2C 1 port.  
  pin assined as below:  


      I2C 1 SDA pin3   
      I2C 1 SCL pin5  
          
  Microchip ATECC608(on I2C port 1)  

# Usage

"git clone --recursive https://github.com/kmwebnet/ECC608-hkdf-create" on your target directory and make -j4.  

# Run this project

execute "./hkdfcreate (target filename)" on termial.  
random 32byte key which uses with cryptsetup will emit to stdout.   
signed HKDF master key will create on same directory with target filename.  

# License

This software is released under the MIT License, see LICENSE.
