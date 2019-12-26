#include <typeinfo>
#include "ecdsa.h"
#include "sha256.h"
#include "tokens.h"

using namespace std;

/* 
 * Test main for token generation
 * generates fake data for now.
 */
int main(int argc, char** argv) {

  assert (argc == 2);
  int party = atoi(argv[1]);

  char ip[15] = "127.0.0.1";
  Balance_l amt;
  RevLockCommitment_l rl;
  MaskCommitment_l paymask_com;
  HMACKeyCommitment_l key_com;
  int port = 12345;
  BitcoinPublicKey_l merch_escrow_pub_key_l;
  BitcoinPublicKey_l merch_dispute_key_l;
  PublicKeyHash_l merch_publickey_hash;
  BitcoinPublicKey_l merch_payout_pub_key_l;
  Nonce_l nonce_l;

  if (party == MERCH) {
	PubKey pkM;
	EcdsaPartialSig_l sig;
	string r = "108792476108599305057612221643697785065475034835954270988586688301027220077907";
    string k_inv = "44657876998057202178264530375095959644163723589174927475562391733096641768603";

    fillEcdsaPartialSig_l(&sig, r, k_inv);
    struct HMACKey_l hmac_key;
    struct Mask_l mask;
	build_masked_tokens_merch(
	  pkM, amt, rl, port, ip,
      paymask_com, key_com, merch_escrow_pub_key_l,
      merch_dispute_key_l, merch_publickey_hash,
      merch_payout_pub_key_l, nonce_l,
      hmac_key,
	  mask, mask, mask, sig, sig, sig);
  } else {
	PubKey pkM;
	State_l w;
    PayToken_l pt_old;
	BitcoinPublicKey_l cust_escrow_pub_key_l;
    BitcoinPublicKey_l cust_payout_pub_key_l;
    PayToken_l pt_return;
    EcdsaSig_l ct_escrow;
    EcdsaSig_l ct_merch;

	build_masked_tokens_cust(
	  pkM, amt, rl, port, ip,
      paymask_com, key_com, merch_escrow_pub_key_l,
      merch_dispute_key_l, merch_publickey_hash,
      merch_payout_pub_key_l, nonce_l,
	  w, w, nullptr, pt_old, cust_escrow_pub_key_l, cust_payout_pub_key_l,
	  pt_return, ct_escrow, ct_merch);
  }

  return 0;
}
