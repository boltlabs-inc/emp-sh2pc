#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens.h"
#include "tokens-misc.h"


using namespace emp;
using namespace std;

#define MERCH ALICE
#define CUST BOB

const int QLEN = 256;

// computes SHA256 hash of the input
// todo; maybe require this in a different format 
// (e.g. padded and in blocks)
void parseSHA256_2l(char cmsg[1024], uint message[2][16]);

// hard-coded conversion of secp256k1 point order 
// (e.g. modulus)
// you can go check that these have the same value
string get_ECDSA_params(); 

// ecdsa-signs a message based on the given parameters
// a message and a partial signature
// returns signature, encoded in Integer
Integer ecdsa_sign(char msg[1024], EcdsaPartialSig_l s);
Integer ecdsa_sign(Integer message[2][16], EcdsaPartialSig_d partialsig);

// ecdsa signs a hashed private message
Integer ecdsa_sign_hashed(Integer broken_digest[8], EcdsaPartialSig_d partialsig);
Integer ecdsa_sign_hashed(Integer digest, EcdsaPartialSig_d partialsig);

