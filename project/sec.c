#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"

#define CLIENT_HELLO_SIZE 38
int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign

void init_sec(int initial_state) {
    state_sec = initial_state;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND){
        generate_private_key(); 
        derive_public_key();
        derive_self_signed_certificate();
        load_ca_public_key("ca_public_key.bin");
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) { 
        load_certificate("server_cert.bin"); 
        load_private_key("server_key.bin"); 
        derive_public_key();
    }
    generate_nonce(nonce, NONCE_SIZE);
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    // This passes it directly to standard input (working like Project 1)
    /* return input_io(buf, max_length); */
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        /* Insert Client Hello sending logic here */
        /*
        Construct a Client Hello to place in the payload in this format...
        - Type: Client Hello (0x00)
        - Length: 35
        - Value...
            - Type: Nonce (0x01)
            - Length: 32
            - Value: 32 Bit Generated Nonce
        This should be placed in the payload of the packet being sent
        */ 
        uint8_t client_hello[CLIENT_HELLO_SIZE];/* Initialize a client-hello buffer */
        client_hello[0] = CLIENT_HELLO;         /* Set Type to be Client_Hello */
        client_hello[1] = 0;                    /* Size of Client_Hello is always 35 */
        client_hello[2] = 35;                   /* Size of Client_Hello is always 35 */
        client_hello[3] = NONCE_CLIENT_HELLO;   /* Set the type to be Nonce*/
        client_hello[4] = 0;                    /* Set the size of the Nonce to be 32 */
        client_hello[5] = NONCE_SIZE;
        /* Nonce is already generated and stored in global nonce*/
        for (int i = 0; i < 32; i++){
            client_hello[i + 6] = nonce[i];
        }
        memcpy(buf, client_hello, CLIENT_HELLO_SIZE);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        /* Instead of return 0, do I return the payload buffer? */
        return sizeof(buf);
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        /* Insert Server Hello sending logic here */
        /*
            Construct Server Hello to place in the payload in this format...
            - Type: Server Hello (0x10)
            - Length: <variable>
            - Value...
                - Type: Nonce (from server) (0x01)
                - Length: 32
                - Value: 32 Bit Generated Nonce
                - Type: Certificate (0xA0)
                - Length: <variable> 
                - Value...
                    - Type: Public Key (0xA1)
                    - Length: <variable>
                    - Value: <variable>
                    - Type: Signature (0xA2)
                    - Length <variable>
                    - Value <variable>
                - Type: Nonce Signature (0x12)
                - Length: <variable>
                - Value: <variable>
        */
        /* Generate all the pieces of the server hello */

        /* 1. Generate the 32 bit nonce (stored in nonce) */
        /* NOTE: Generated in init_sec() */
        /* 2. Generate the certificate (size is stored in cert_size; certificate is stored in cert) */
        /* NOTE: Generated in init_sec() */
        /* 3. Generate nonce signature */
        int offset = 0;
        uint8_t *nonce_signature;
        ssize_t sig_size = sign(peer_nonce, NONCE_SIZE, nonce_signature);
        /* Constructing server_hello... */
        int server_hello_size = NONCE_SIZE + cert_size + sig_size + 12;
        uint8_t server_hello[server_hello_size];
        /* Server Hello Header*/
        server_hello[offset++] = SERVER_HELLO;
        server_hello[offset++] = ((server_hello_size - 3) >> 8) & 0xFF;
        server_hello[offset++] = (server_hello_size - 3) & 0xFF;
        /* Nonce Component */
        server_hello[offset++] = NONCE_SERVER_HELLO;
        server_hello[offset++] = (NONCE_SIZE >> 8) & 0xFF;
        server_hello[offset++] = NONCE_SIZE & 0xFF;
        memcpy(server_hello[offset], nonce, NONCE_SIZE);
        offset += NONCE_SIZE;
        /* Certificate Component */
        server_hello[offset++] = CERTIFICATE;
        server_hello[offset++] = (cert_size >> 8) & 0xFF;
        server_hello[offset++] = cert_size & 0xFF;
        memcpy(server_hello[offset], certificate, cert_size);
        offset += cert_size;
        /* Nonce Signature Component */
        server_hello[offset++] = NONCE_SIGNATURE_SERVER_HELLO;
        server_hello[offset++] = (sig_size >> 8) & 0xFF;
        server_hello[offset++] = sig_size & 0xFF;
        memcpy(server_hello[offset], nonce_signature, sig_size);
        offset += sig_size;    

        /* Copying it all to the main buffer */
        memcpy(buf, server_hello, server_hello_size);

        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return sizeof(buf);
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
        print("SEND KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request sending logic here */

        state_sec = CLIENT_FINISHED_AWAIT;
        return 0;
    }
    case SERVER_FINISHED_SEND: {
        print("SEND FINISHED");

        /* Insert Finished sending logic here */

        state_sec = DATA_STATE;
        return 0;
    }
    case DATA_STATE: {
        /* Insert Data sending logic here */

        // PT refers to the amount you read from stdin in bytes
        // CT refers to the resulting ciphertext size
        // fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, cip_size);

        return 0;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    // This passes it directly to standard output (working like Project 1)
    // return output_io(buf, length); 

    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");
        /* Insert Client Hello receiving logic here */

        /* 1. Place what you recieved in the peer nonce */
        memcpy(peer_nonce, buf[6], NONCE_SIZE);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");

        /* Insert Server Hello receiving logic here */

        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request receiving logic here */

        state_sec = SERVER_FINISHED_SEND;
        break;
    }
    case CLIENT_FINISHED_AWAIT: {
        if (*buf != FINISHED)
            exit(4);

        print("RECV FINISHED");

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        if (*buf != DATA)
            exit(4);

        /* Insert Data receiving logic here */

        // PT refers to the resulting plaintext size in bytes
        // CT refers to the received ciphertext size
        // fprintf(stderr, "RECV DATA PT %ld CT %hu\n", data_len, cip_len);
        break;
    }
    default:
        break;
    }
}
