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

/* Helper function to print buffers*/
#define MIN(a, b) (a < b) ? a : b
static inline void print_tlv(uint8_t* buffer, size_t len) {
    uint8_t* buf = buffer;

    while (buf - buffer < len) {
        uint8_t type = *buf;
        fprintf(stderr, "Type: 0x%02x\n", type);
        buf += 1;
        if (buf - buffer >= len)
            return;

        uint16_t length = ntohs(*((uint16_t*) buf));
        buf += 2;
        fprintf(stderr, "Length: %hu\n", length);

        if (type == CLIENT_HELLO || type == SERVER_HELLO ||
            type == KEY_EXCHANGE_REQUEST || type == FINISHED ||
            type == CERTIFICATE || type == DATA)
            continue;
        else {
            uint16_t min_length = MIN(len - (buf - buffer), length);
            print_hex(buf, min_length);
            buf += min_length;
        }
    }
}

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
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
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
        return CLIENT_HELLO_SIZE;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        /* Generate all the pieces of the server hello */
        /* 1. Generate the 32 byte nonce (stored in nonce) */
        /* NOTE: Generated in init_sec() */
        /* 2. Generate the certificate (size is stored in cert_size; certificate is stored in cert) */
        /* NOTE: Generated in init_sec() */
        /* 3. Generate nonce signature */
        int offset = 0;
        uint8_t nonce_signature[255];
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
        server_hello[offset++] = NONCE_SIZE >> 8;
        server_hello[offset++] = NONCE_SIZE & 0xFF;
        memcpy(&server_hello[offset], nonce, NONCE_SIZE);
        offset += NONCE_SIZE;
        /* Certificate Component */
        /* NOTE: The cert header is already there when you load it */
        memcpy(&server_hello[offset], certificate, cert_size);
        offset += cert_size;
        /* Nonce Signature Component */
        server_hello[offset++] = NONCE_SIGNATURE_SERVER_HELLO;
        server_hello[offset++] = sig_size >> 8;
        server_hello[offset++] = sig_size & 0xFF;
        memcpy(&server_hello[offset], nonce_signature, sig_size);
        offset += sig_size;    

        /* Copying it all to the main buffer */
        memcpy(buf, server_hello, server_hello_size); 
        
        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return server_hello_size;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
        print("SEND KEY EXCHANGE REQUEST");
        /* 1. Generate Nonce Signature */
        uint8_t nonce_signature[255];
        size_t sig_len = sign(peer_nonce, NONCE_SIZE, nonce_signature);
                            //key exchange header + cert header + cert_size + nonce_sig header + sig_len
        int key_exchange_len = 3 + 3 + cert_size + 3 + sig_len;
        /* 2. Creating the key exchange component */
        int offset = 0;
        uint8_t key_exchange[key_exchange_len];
        /* Key Exchange Header*/
        key_exchange[offset++] = KEY_EXCHANGE_REQUEST;
        key_exchange[offset++] = ((key_exchange_len - 3) >> 8);
        key_exchange[offset++] = (key_exchange_len - 3) & 0xFF;
        /* Copying the Certificate In*/
        memcpy(&key_exchange[offset], certificate, cert_size);
        offset += cert_size;
        /* Nonce Signature Header */
        key_exchange[offset++] = NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST;
        key_exchange[offset++] = sig_len >> 8;
        key_exchange[offset++] = sig_len & 0xFF;
        memcpy(&key_exchange[offset], nonce_signature, sig_len);
        offset += sig_len;
        
        fprintf(stderr, "Offset: %d\n", offset);
        fprintf(stderr, "Offset: %d\n", key_exchange_len);
        memcpy(buf, key_exchange, key_exchange_len);

        state_sec = CLIENT_FINISHED_AWAIT;
        return key_exchange_len;
    }
    case SERVER_FINISHED_SEND: {
        print("SEND FINISHED");

        /* Insert Finished sending logic here */
        uint8_t finished[3];
        finished[0] = FINISHED;
        finished[1] = 0;
        finished[2] = 0;

        memcpy(buf, finished, 3);

        state_sec = DATA_STATE;
        return 3;
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
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");

        /* 1. Place what you recieved in the peer nonce */
        memcpy(&peer_nonce, buf + 6, NONCE_SIZE);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");
        /* Getting the offset of the certificate and its length */
        int cert_loc = 3 + 3 + NONCE_SIZE;                          //certificate idx
        int cert_len = (buf[cert_loc + 1] << 8) + buf[cert_loc + 2];//certificate len (in server hello)

        /* Getting the offset of the nonce_sig and its length */
        int nonce_sig_loc = 3 + 3 + NONCE_SIZE + 3 + cert_len;    //nonce-sig idx
        int nonce_sig_len = (buf[nonce_sig_loc + 1] << 8) + buf[nonce_sig_loc + 2];           //get the nonce signature length
    
        /* Getting the public key and signature length*/
        int pk_len = (buf[cert_loc + 4] << 8) + buf[cert_loc + 5];                            //get the public key length
        int sig_len = (buf[cert_loc + 6 + pk_len + 1] << 8) + buf[cert_loc + 6 + pk_len + 2]; //get the signature length 

        /* Load the public key */
        load_peer_public_key(buf + cert_loc + 6, pk_len);          //load the public key
        
        /* 1. Attempt to verify the certificate with the public key */
        
        int cert_check = verify(buf + cert_loc + 6,                 //pk location 
                                pk_len,                             //pk length
                                buf + cert_loc + 6 + pk_len + 3,    //sig location
                                sig_len,                            //sig length
                                ec_ca_public_key);                  //cert auth pk
        if (cert_check != 1){
            fprintf(stderr, "Invalid Certificate");
            exit(1);
        }
        
        /* 2. Attempt to verify that the client nonce was signed by the server */
        int nonce_check = verify(nonce,                            //nonce value
                                NONCE_SIZE,                        //nonce size
                                buf + nonce_sig_loc + 3,           //nonce sig location 
                                nonce_sig_len,                     //nonce sig length
                                ec_peer_public_key);               //ec_peer_public_key
        if (nonce_check != 1){
            fprintf(stderr, "Invalid Nonce Signature");
            exit(2);
        }

        /* 3. Save server's nonce in peer nonce */
        memcpy(&peer_nonce, buf + 6, NONCE_SIZE);

        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        /* Get the certificate offset and length */
        int cert_loc = 3;
        int cert_len = (buf[cert_loc + 1] << 8) + (buf[cert_loc + 2]);
        
        /* Get the public key offset and length*/
        int pk_loc = 3 + 3;
        int pk_len = (buf[pk_loc + 1] << 8) + buf[pk_loc + 2];
        load_peer_public_key(buf + pk_loc + 3, pk_len);

        /* Get the signature offset and length*/
        int sig_loc = 3 + 3 + 3 + pk_len;
        int sig_len = (buf[sig_loc + 1] << 8) + buf[sig_loc + 2];

        /* 1. Verify that the certificate was self-signed */
        int cert_check = verify(buf + pk_loc + 3,       //pk loc
                                pk_len,                 //pk len
                                buf + sig_loc + 3,      //signature loc
                                sig_len,                //signature len
                                ec_peer_public_key);    //peer public key
        if (cert_check != 1){
            fprintf(stderr, "Cert Check Failed!\n");
            exit(1);
        }

        /* Get the nonce signature offset and length */
        int nonce_sig_loc = 3 + 3 + cert_len;
        int nonce_sig_len = (buf[nonce_sig_loc + 1] << 8) + buf[nonce_sig_loc + 2];

        /* 2. Verify the nonce signature */
        int nonce_sig_check = verify(nonce,
                                    NONCE_SIZE,
                                    buf + nonce_sig_loc + 3,
                                    nonce_sig_len,
                                    ec_peer_public_key);
        fprintf(stderr, "Nonce Signature Check: %d\n", nonce_sig_check);
        if (nonce_sig_check != 1){
            fprintf(stderr, "Nonce Signature Check Failed!\n");
            exit(2);
        }
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
