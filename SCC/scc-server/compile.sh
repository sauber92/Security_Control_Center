sudo gcc -o server server.c sslthread.c sslthread.h Attestation_server.c Attestation_server.h Firmware_server.c Firmware_server.h -lssl -lcrypto -lpthread -L/home/ubuntu/openssl-1.1.0e
