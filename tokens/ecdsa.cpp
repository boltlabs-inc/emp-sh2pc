#include <typeinfo>
#include "ecdsa.h"
#include "sha256.h"

// parses a 1024 char array (of 0/1s) into a 2-block sha256 input 
// input: char [1024]
// output: fills in uint [2][16]
//  TODO make some test vectors, seriously
//  TODO maybe move the parsing code to sha256 module
//  TODO maybe move this to a distribute_?? function
//
void parseSHA256_2l(char cmsg[1024], uint message[2][16]) {
  // convert to bools TODO: test this section
  bool msg[1024];
  for (int i=0; i<1024; i++) {
    assert (cmsg[i] == '0' || cmsg[i] == '1');
    msg[i] = (cmsg[i] == 1);
  }
  // convert to Integer
  //uint message[2][16] = {0};
  uint shft = 0;
  uint block = 0;
  uint byte = 0;
  uint build = 0;
  for (int i=1023; i>0; i--) {
    build |= msg[i] << shft;

    shft++;
    if (shft == 32) {
      message[block][byte] = build;
      byte++;
      build = 0;
      shft = 0;
    }
    if (byte == 16) {
      block++;
      byte = 0;
    }
  }
}

// hard-coded conversion of secp256k1 point order 
// (e.g. modulus)
// you can go check that these have the same value
string get_ECDSA_params() {
  string qhex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
  return "115792089237316195423570985008687907852837564279074904382605163141518161494337";
}

// signs a message using the Ecdsa partial signature 
Integer ecdsa_sign(Integer message[2][16], EcdsaPartialSig_d partialsig) {
  Integer result[8];

  computeSHA256_2d(message, result);
  Integer hash = composeSHA256result(result);
  return ecdsa_sign_hashed(hash, partialsig);
}

// ecdsa-signs a message based on the given parameters
// parameters here are appended -c because they're in the clear
// mc : message text (in the clear)
// pubsig : partial ecdsa signature in the clear (see token.h)
Integer ecdsa_sign(char msg[1024], EcdsaPartialSig_l pubsig) {
  EcdsaPartialSig_d partialsig = distribute_EcdsaPartialSig(pubsig);

  // parse input for hashing
  uint parsed_msg[2][16];
  parseSHA256_2l(msg, parsed_msg);

  // hash and sign
  Integer result[8];
  computeSHA256_2l(parsed_msg, result);
  Integer hash = composeSHA256result(result);
  return ecdsa_sign_hashed(hash, partialsig);
}

Integer ecdsa_sign_hashed(Integer broken_digest[8], EcdsaPartialSig_d partialsig) {
  Integer digest = composeSHA256result(broken_digest);
  return ecdsa_sign_hashed(digest, partialsig);
}

Integer ecdsa_sign_hashed(Integer digest, EcdsaPartialSig_d partialsig) {
  // get shared/fixed q
  Integer q(257, get_ECDSA_params(), PUBLIC);

  digest.resize(257, true);
  digest = digest % q;

  // can we keep q in the clear and use it as the modulus?
  Integer s = digest + partialsig.r;
  s = s % q;

  s.resize(513,true);
  q.resize(513,true);
  s = partialsig.k_inv * s;
  s = s % q;

  s.resize(256,true);

  return s;
}


