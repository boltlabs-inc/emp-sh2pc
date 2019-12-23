/*
 *
 *
 */
#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens/tokens-misc.h"
#include "tokens/hmac.h"
#include "tokens/sha256.h"
using namespace emp;
using namespace std;

// crypto++ headers
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/hmac.h"
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
#include "cryptopp/secblock.h"
#define byte unsigned char

// boost header to compare strings
#include <boost/algorithm/string.hpp>

string run_secure_bitcoin();
string test_output(Integer result[8]);

void validate_transactions_local(State_d new_state_d, 
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, PublicKeyHash_d merch_publickey_hash_d,
  Integer escrow_digest[8]);

void validate_transactions_local_first(State_d new_state_d, 
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, PublicKeyHash_d merch_publickey_hash_d,
  Integer escrow_digest[8]);

void validate_transactions_local_second(State_d new_state_d, 
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, PublicKeyHash_d merch_publickey_hash_d,
  Integer escrow_digest[8]);

Integer compose_buffer(Integer buffer[16]) {
  Integer thirtytwo(512, 32, PUBLIC);
  buffer[0].resize(512, false);
  Integer to_return = buffer[0];
  for(int i=1; i<16; i++) {
    buffer[i].resize(512, false);
    to_return = (to_return << thirtytwo) | buffer[i];
  }
  return to_return;
}

// The msgs we are signing are 116 bytes long, or 29 ints long
void test_end_to_end() {

  string digest_preimage = "020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4000000004752210342da23a1de903cd7a141a99b5e8051abfcd4d2d1b3c2112bac5c8997d9f12a002103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752ae00c2eb0b00000000ffffffffbf2c6d3e3f83ea5aadeb2a4076c3ce54d9f3346b0ee535270c9821eff8cf1afe0000000001000000";

  string actual = run_secure_bitcoin();

  boost::algorithm::to_lower(actual);

  cout << "Computed Final Digest=" << actual << endl;
  cout << "Actual Final Digest=7efadfeb9821ad95cb37a0d31c55e2fc21b9337af11b60151ac728b154da5d49" << endl;

  // assert ( expected.compare(actual) == 0);
  // assert ( expected.compare("af4e2daca29f7c6e68d6a0d536eec5a96527650a59506eea815062b782cc99bb") == 0 );

  cout << "Hashed the thing correctly." << endl;
}


// test hmac implementation 
string run_secure_bitcoin() {

  string rl_s = "f8345a21a55dc665b65c8dcfb49488b8e4f337d5c9bb843603f7222a892ce941";
  string balance_cust_s = "00e1f50500000000";
  string balance_merch_s = "00e1f50500000000";
  string txid_escrow_s = "e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4";
  string hashouts_escrow = "7d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d738";

  string merch_escrow_pub_key_s = "0342da23a1de903cd7a141a99b5e8051abfcd4d2d1b3c2112bac5c8997d9f12a00000000";
  string cust_escrow_pub_key_s  = "03fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d7000000";
  string merch_dispute_key_s    = "0253be79afe84fd9342c1f52024379b6da6299ea98844aee23838e8e678a765f7c000000";
  string merch_pubkey_hash_s    = "d4354803d10e77eccfc3bf06c152ae694d05d381";
  string cust_payout_pub_key_s  = "03195e272df2310ded35f9958fd0c2847bf73b5b429a716c005d465009bd768641000000";

  // State_l new_state_l {
  //   struct Nonce_l nonce; // doesnt matter
  //   struct RevLock_l rl; = f8345a21a55dc665b65c8dcfb49488b8e4f337d5c9bb843603f7222a892ce941
  //   int64_t balance_cust; = 00e1f05000000000 // FOR NOW!  NEED TO FLIP ENDIANNESS LATER.  THIS IS PROPER LITTLE ENDIAN
  //   int64_t balance_merch; = 00e1f05000000000
  //   struct Txid_l txid_merch; = doesnt matter
  //   struct Txid_l txid_escrow; = e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4
  //   struct Txid_l HashPrevOuts_merch; = doesnt matter
  //   struct Txid_l HashPrevOuts_escrow = 7d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d738;
  // }

  string temp;

  struct State_l state_l;

  struct BitcoinPublicKey_l merch_escrow_pub_key_l;
  struct BitcoinPublicKey_l merch_dispute_key_l;
  struct BitcoinPublicKey_l cust_escrow_pub_key_l;
  struct BitcoinPublicKey_l cust_payout_pub_key_l;

  struct PublicKeyHash_l merch_pubkey_hash_l;

  for(int i=0; i<8; i++) {
    temp = rl_s.substr(i*8, 8);
    state_l.rl.revlock[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<2; i++) {
    temp = balance_cust_s.substr(i*8, 8);
    state_l.balance_cust.balance[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

    for(int i=0; i<2; i++) {
    temp = balance_merch_s.substr(i*8, 8);
    state_l.balance_merch.balance[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = txid_escrow_s.substr(i*8, 8);
    state_l.txid_escrow.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = hashouts_escrow.substr(i*8, 8);
    state_l.HashPrevOuts_escrow.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<9; i++) {
    temp = merch_escrow_pub_key_s.substr(i*8, 8);
    merch_escrow_pub_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<9; i++) {
    temp = merch_dispute_key_s.substr(i*8, 8);
    merch_dispute_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<9; i++) {
    temp = cust_escrow_pub_key_s.substr(i*8, 8);
    cust_escrow_pub_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<9; i++) {
    temp = cust_payout_pub_key_s.substr(i*8, 8);
    cust_payout_pub_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<5; i++) {
    temp = merch_pubkey_hash_s.substr(i*8, 8);
    merch_pubkey_hash_l.hash[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }


  State_d state_d = distribute_State(state_l, CUST);
  BitcoinPublicKey_d merch_escrow_pub_key_d = distribute_BitcoinPublicKey(merch_escrow_pub_key_l, PUBLIC);
  BitcoinPublicKey_d merch_dispute_key_d = distribute_BitcoinPublicKey(merch_dispute_key_l, PUBLIC);
  BitcoinPublicKey_d cust_escrow_pub_key_d = distribute_BitcoinPublicKey(cust_escrow_pub_key_l, CUST);
  BitcoinPublicKey_d cust_payout_pub_key_d = distribute_BitcoinPublicKey(cust_payout_pub_key_l, CUST);
  PublicKeyHash_d merch_pubkey_hash_d = distribute_PublicKeyHash(merch_pubkey_hash_l, PUBLIC);


/*  FIRST PART OF THE TEST */

  Integer customer_delayed_script_hash[8];

  validate_transactions_local_first(state_d,
    cust_escrow_pub_key_d, cust_payout_pub_key_d,
    merch_escrow_pub_key_d, merch_dispute_key_d, merch_pubkey_hash_d, customer_delayed_script_hash);

  Integer customer_delayed_script = composeSHA256result(customer_delayed_script_hash);
  string customer_delayed_script_hash_string = customer_delayed_script.reveal_unsigned(PUBLIC,16);
  while (customer_delayed_script_hash_string.length() < 64) {
    customer_delayed_script_hash_string = '0' + customer_delayed_script_hash_string;
  }

  cout << "Computed customer_delayed_script_hash=" << customer_delayed_script_hash_string << endl;
  cout << "Actual customer_delayed_script_hash=67cb20e705c4eb4363194a74d2f743afc1c9ee3cd741d45e21268b16add04f8b" << endl;

/*  SECOND PART OF THE TEST */

  Integer hash_outputs[8];

  validate_transactions_local_second(state_d,
    cust_escrow_pub_key_d, cust_payout_pub_key_d,
    merch_escrow_pub_key_d, merch_dispute_key_d, merch_pubkey_hash_d, hash_outputs);

  Integer hash_o = composeSHA256result(hash_outputs);
  string hash_outputs_string = hash_o.reveal_unsigned(PUBLIC,16);
  while (hash_outputs_string.length() < 64) {
    hash_outputs_string = '0' + hash_outputs_string;
  }

  cout << "Computed hash_outputs=" << hash_outputs_string << endl;
  cout << "Actual hash_outputs=bf2c6d3e3f83ea5aadeb2a4076c3ce54d9f3346b0ee535270c9821eff8cf1afe" << endl;

/*   THIRD PART OF THE TEST  */

  Integer escrow_digest[8];

  validate_transactions_local(state_d,
    cust_escrow_pub_key_d, cust_payout_pub_key_d,
    merch_escrow_pub_key_d, merch_dispute_key_d, merch_pubkey_hash_d, escrow_digest);
  
  Integer hash = composeSHA256result(escrow_digest);
  string res = hash.reveal_unsigned(PUBLIC,16);
  while (res.length() < 64) {
    res = '0' + res;
  }
  return res;
}

void validate_transactions_local_first(State_d new_state_d, 
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, PublicKeyHash_d merch_publickey_hash_d,
  Integer escrow_digest[8]) {

  // 112 bytes --> 896
  Integer customer_delayed_script_hash_preimage[2][16];

  // OPCODE || 1 byte of Rev Lock
  customer_delayed_script_hash_preimage[0][0] = Integer(32, 1671962624 /*0x63a92000*/, PUBLIC) | /* First byte of revlock*/(new_state_d.rl.revlock[0] >> 24);

  // 31 remaining bytes of Rev Lock
  customer_delayed_script_hash_preimage[0][1] = (/* last 3 bytes */ new_state_d.rl.revlock[0] << 8) | ( /* first byte of the next int */ new_state_d.rl.revlock[1] >> 24);
  customer_delayed_script_hash_preimage[0][2] = (new_state_d.rl.revlock[1] << 8) | (new_state_d.rl.revlock[2] >> 24);
  customer_delayed_script_hash_preimage[0][3] = (new_state_d.rl.revlock[2] << 8) | (new_state_d.rl.revlock[3] >> 24);
  customer_delayed_script_hash_preimage[0][4] = (new_state_d.rl.revlock[3] << 8) | (new_state_d.rl.revlock[4] >> 24);
  customer_delayed_script_hash_preimage[0][5] = (new_state_d.rl.revlock[4] << 8) | (new_state_d.rl.revlock[5] >> 24);
  customer_delayed_script_hash_preimage[0][6] = (new_state_d.rl.revlock[5] << 8) | (new_state_d.rl.revlock[6] >> 24);
  customer_delayed_script_hash_preimage[0][7] = (new_state_d.rl.revlock[6] << 8) | (new_state_d.rl.revlock[7] >> 24);
  customer_delayed_script_hash_preimage[0][8] = (new_state_d.rl.revlock[7] << 8) | Integer(32, 136 /*0x00000088*/, PUBLIC);

  customer_delayed_script_hash_preimage[0][9]  = Integer(32, 553648128, PUBLIC) | merch_dispute_key_d.key[0] >> 8; //0x21000000 // taking 3 bytes from the key
  customer_delayed_script_hash_preimage[0][10] = (merch_dispute_key_d.key[0] << 24) | (merch_dispute_key_d.key[1] >> 8); // byte 4-7
  customer_delayed_script_hash_preimage[0][11] = (merch_dispute_key_d.key[1] << 24) | (merch_dispute_key_d.key[2] >> 8); // byte 8-11
  customer_delayed_script_hash_preimage[0][12] = (merch_dispute_key_d.key[2] << 24) | (merch_dispute_key_d.key[3] >> 8); // bytes 12-15
  customer_delayed_script_hash_preimage[0][13] = (merch_dispute_key_d.key[3] << 24) | (merch_dispute_key_d.key[4] >> 8); // bytes 16-19
  customer_delayed_script_hash_preimage[0][14] = (merch_dispute_key_d.key[4] << 24) | (merch_dispute_key_d.key[5] >> 8); // bytes 20-23
  customer_delayed_script_hash_preimage[0][15] = (merch_dispute_key_d.key[5] << 24) | (merch_dispute_key_d.key[6] >> 8); // bytes 24-27
  customer_delayed_script_hash_preimage[1][0]  = (merch_dispute_key_d.key[6] << 24) | (merch_dispute_key_d.key[7] >> 8); // bytes 28-31
  customer_delayed_script_hash_preimage[1][1]  = (merch_dispute_key_d.key[7] << 24) | (merch_dispute_key_d.key[8] >> 8) | Integer(32, 26368/*0x00006700*/, PUBLIC) | Integer(32,2 /*0x000002*/, PUBLIC); // bytes 32-33 // 0x67

  // This previous last byte and the following to bytes is the delay.  We should talk about how long we want them to be
  customer_delayed_script_hash_preimage[1][2]  = Integer(32, 3473211392 /*0xcf050000*/, PUBLIC) | Integer(32, 45685/*0x0000b275*/, PUBLIC);
  customer_delayed_script_hash_preimage[1][3]  = Integer(32, 553648128 /*0x21000000*/, PUBLIC)  | (cust_payout_pub_key_d.key[0] >> 8);
  customer_delayed_script_hash_preimage[1][4]  = (cust_payout_pub_key_d.key[0] << 24) | (cust_payout_pub_key_d.key[1] >> 8);
  customer_delayed_script_hash_preimage[1][5]  = (cust_payout_pub_key_d.key[1] << 24) | (cust_payout_pub_key_d.key[2] >> 8);
  customer_delayed_script_hash_preimage[1][6]  = (cust_payout_pub_key_d.key[2] << 24) | (cust_payout_pub_key_d.key[3] >> 8);
  customer_delayed_script_hash_preimage[1][7]  = (cust_payout_pub_key_d.key[3] << 24) | (cust_payout_pub_key_d.key[4] >> 8);
  customer_delayed_script_hash_preimage[1][8]  = (cust_payout_pub_key_d.key[4] << 24) | (cust_payout_pub_key_d.key[5] >> 8);
  customer_delayed_script_hash_preimage[1][9]  = (cust_payout_pub_key_d.key[5] << 24) | (cust_payout_pub_key_d.key[6] >> 8);
  customer_delayed_script_hash_preimage[1][10] = (cust_payout_pub_key_d.key[6] << 24) | (cust_payout_pub_key_d.key[7] >> 8);
  customer_delayed_script_hash_preimage[1][11] = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | Integer(32, 26796/*0x000068ac*/, PUBLIC);

  customer_delayed_script_hash_preimage[1][12] = Integer(32, -2147483648/*0x80000000*/, PUBLIC); 
  customer_delayed_script_hash_preimage[1][13] = Integer(32, 0, PUBLIC); //0x00000000; 
  customer_delayed_script_hash_preimage[1][14] = Integer(32, 0, PUBLIC); //0x00000000; 
  customer_delayed_script_hash_preimage[1][15] = Integer(32, 896, PUBLIC); 

  computeSHA256_2d(customer_delayed_script_hash_preimage, escrow_digest);

}

void validate_transactions_local_second(State_d new_state_d, 
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, PublicKeyHash_d merch_publickey_hash_d,
  Integer escrow_digest[8]) {

 // 112 bytes --> 896
  Integer customer_delayed_script_hash_preimage[2][16];

  // OPCODE || 1 byte of Rev Lock  0x63a82000  1671962624
  customer_delayed_script_hash_preimage[0][0] = Integer(32, 1671962624 /*0x63a92000*/, PUBLIC) | /* First byte of revlock*/(new_state_d.rl.revlock[0] >> 24);

  // 31 remaining bytes of Rev Lock
  customer_delayed_script_hash_preimage[0][1] = (/* last 3 bytes */ new_state_d.rl.revlock[0] << 8) | ( /* first byte of the next int */ new_state_d.rl.revlock[1] >> 24);
  customer_delayed_script_hash_preimage[0][2] = (new_state_d.rl.revlock[1] << 8) | (new_state_d.rl.revlock[2] >> 24);
  customer_delayed_script_hash_preimage[0][3] = (new_state_d.rl.revlock[2] << 8) | (new_state_d.rl.revlock[3] >> 24);
  customer_delayed_script_hash_preimage[0][4] = (new_state_d.rl.revlock[3] << 8) | (new_state_d.rl.revlock[4] >> 24);
  customer_delayed_script_hash_preimage[0][5] = (new_state_d.rl.revlock[4] << 8) | (new_state_d.rl.revlock[5] >> 24);
  customer_delayed_script_hash_preimage[0][6] = (new_state_d.rl.revlock[5] << 8) | (new_state_d.rl.revlock[6] >> 24);
  customer_delayed_script_hash_preimage[0][7] = (new_state_d.rl.revlock[6] << 8) | (new_state_d.rl.revlock[7] >> 24);
  customer_delayed_script_hash_preimage[0][8] = (new_state_d.rl.revlock[7] << 8) | Integer(32, 136 /*0x00000088*/, PUBLIC);

  customer_delayed_script_hash_preimage[0][9]  = Integer(32, 553648128, PUBLIC) | merch_dispute_key_d.key[0] >> 8; //0x21000000 // taking 3 bytes from the key
  customer_delayed_script_hash_preimage[0][10] = (merch_dispute_key_d.key[0] << 24) | (merch_dispute_key_d.key[1] >> 8); // byte 4-7
  customer_delayed_script_hash_preimage[0][11] = (merch_dispute_key_d.key[1] << 24) | (merch_dispute_key_d.key[2] >> 8); // byte 8-11
  customer_delayed_script_hash_preimage[0][12] = (merch_dispute_key_d.key[2] << 24) | (merch_dispute_key_d.key[3] >> 8); // bytes 12-15
  customer_delayed_script_hash_preimage[0][13] = (merch_dispute_key_d.key[3] << 24) | (merch_dispute_key_d.key[4] >> 8); // bytes 16-19
  customer_delayed_script_hash_preimage[0][14] = (merch_dispute_key_d.key[4] << 24) | (merch_dispute_key_d.key[5] >> 8); // bytes 20-23
  customer_delayed_script_hash_preimage[0][15] = (merch_dispute_key_d.key[5] << 24) | (merch_dispute_key_d.key[6] >> 8); // bytes 24-27
  customer_delayed_script_hash_preimage[1][0]  = (merch_dispute_key_d.key[6] << 24) | (merch_dispute_key_d.key[7] >> 8); // bytes 28-31
  customer_delayed_script_hash_preimage[1][1]  = (merch_dispute_key_d.key[7] << 24) | (merch_dispute_key_d.key[8] >> 8) | Integer(32, 26368/*0x00006700*/, PUBLIC) | Integer(32,2 /*0x000002*/, PUBLIC); // bytes 32-33 // 0x67

  // This previous last byte and the following to bytes is the delay.  We should talk about how long we want them to be
  customer_delayed_script_hash_preimage[1][2]  = Integer(32, 3473211392 /*0xcf050000*/, PUBLIC) | Integer(32, 45685/*0x0000b275*/, PUBLIC);
  customer_delayed_script_hash_preimage[1][3]  = Integer(32, 553648128 /*0x21000000*/, PUBLIC)  | (cust_payout_pub_key_d.key[0] >> 8);
  customer_delayed_script_hash_preimage[1][4]  = (cust_payout_pub_key_d.key[0] << 24) | (cust_payout_pub_key_d.key[1] >> 8);
  customer_delayed_script_hash_preimage[1][5]  = (cust_payout_pub_key_d.key[1] << 24) | (cust_payout_pub_key_d.key[2] >> 8);
  customer_delayed_script_hash_preimage[1][6]  = (cust_payout_pub_key_d.key[2] << 24) | (cust_payout_pub_key_d.key[3] >> 8);
  customer_delayed_script_hash_preimage[1][7]  = (cust_payout_pub_key_d.key[3] << 24) | (cust_payout_pub_key_d.key[4] >> 8);
  customer_delayed_script_hash_preimage[1][8]  = (cust_payout_pub_key_d.key[4] << 24) | (cust_payout_pub_key_d.key[5] >> 8);
  customer_delayed_script_hash_preimage[1][9]  = (cust_payout_pub_key_d.key[5] << 24) | (cust_payout_pub_key_d.key[6] >> 8);
  customer_delayed_script_hash_preimage[1][10] = (cust_payout_pub_key_d.key[6] << 24) | (cust_payout_pub_key_d.key[7] >> 8);
  customer_delayed_script_hash_preimage[1][11] = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | Integer(32, 26796/*0x000068ac*/, PUBLIC);

  customer_delayed_script_hash_preimage[1][12] = Integer(32, -2147483648/*0x80000000*/, PUBLIC); 
  customer_delayed_script_hash_preimage[1][13] = Integer(32, 0, PUBLIC); //0x00000000; 
  customer_delayed_script_hash_preimage[1][14] = Integer(32, 0, PUBLIC); //0x00000000; 
  customer_delayed_script_hash_preimage[1][15] = Integer(32, 896, PUBLIC); 

  Integer customer_delayed_script_hash[8];

  computeSHA256_2d(customer_delayed_script_hash_preimage, customer_delayed_script_hash);

  // 150 bytes
  Integer hash_outputs_preimage[3][16];

  hash_outputs_preimage[0][0]  = new_state_d.balance_cust.balance[0];// first bytes of customer balance // FIX ENDIANNESS
  hash_outputs_preimage[0][1]  = new_state_d.balance_cust.balance[1];// second bytes of customer blanace // FIX ENDIANNESS
  hash_outputs_preimage[0][2]  = Integer(32, 570433536 /*0x22002000*/, PUBLIC) | (customer_delayed_script_hash[0] >> 24); // OPCODE and the first byte of the prev hash output
  hash_outputs_preimage[0][3]  = (customer_delayed_script_hash[0] << 8) | (customer_delayed_script_hash[1] >> 24); // end of byte 1 and first byte of 2...
  hash_outputs_preimage[0][4]  = (customer_delayed_script_hash[1] << 8) | (customer_delayed_script_hash[2] >> 24);
  hash_outputs_preimage[0][5]  = (customer_delayed_script_hash[2] << 8) | (customer_delayed_script_hash[3] >> 24);
  hash_outputs_preimage[0][6]  = (customer_delayed_script_hash[3] << 8) | (customer_delayed_script_hash[4] >> 24);
  hash_outputs_preimage[0][7]  = (customer_delayed_script_hash[4] << 8) | (customer_delayed_script_hash[5] >> 24);
  hash_outputs_preimage[0][8]  = (customer_delayed_script_hash[5] << 8) | (customer_delayed_script_hash[6] >> 24);
  hash_outputs_preimage[0][9]  = (customer_delayed_script_hash[6] << 8) | (customer_delayed_script_hash[7] >> 24);
  hash_outputs_preimage[0][10] = (customer_delayed_script_hash[7] << 8) |  (new_state_d.balance_merch.balance[0] >> 24);/*first byte of merch balance >> 24*/;
  hash_outputs_preimage[0][11] =  (new_state_d.balance_merch.balance[0] << 8) | (new_state_d.balance_merch.balance[1] >> 24);
  hash_outputs_preimage[0][12] =  (new_state_d.balance_merch.balance[1] << 8) | Integer(32, 22 /*0x00000016*/, PUBLIC);
  hash_outputs_preimage[0][13] = Integer(32, 1310720 /*0x00140000*/, PUBLIC) | (merch_publickey_hash_d.hash[0] >> 16);
  hash_outputs_preimage[0][14] = (merch_publickey_hash_d.hash[0] << 16) | (merch_publickey_hash_d.hash[1] >> 16);
  hash_outputs_preimage[0][15] = (merch_publickey_hash_d.hash[1] << 16) | (merch_publickey_hash_d.hash[2] >> 16);
  hash_outputs_preimage[1][0]  = (merch_publickey_hash_d.hash[2] << 16) | (merch_publickey_hash_d.hash[3] >> 16);
  hash_outputs_preimage[1][1]  = (merch_publickey_hash_d.hash[3] << 16) | (merch_publickey_hash_d.hash[4] >> 16);
  hash_outputs_preimage[1][2]  = (merch_publickey_hash_d.hash[4] << 16) | Integer(32, 0 /*0x00000000*/, PUBLIC); //Two bytes of the OP_Return Amount
  hash_outputs_preimage[1][3]  = Integer(32, 0, PUBLIC); // middle 4 bytes of OP_RETURN amount
  hash_outputs_preimage[1][4]  = Integer(32, 17258/*0x0000376a*/,PUBLIC); // OPRETURN FORMATTING 
  hash_outputs_preimage[1][5] = Integer(32, 1090519040/*0x41000000*/,PUBLIC)/*last byte of opreturn formatting */ | (new_state_d.rl.revlock[0] >> 8); 

  hash_outputs_preimage[1][6]  = (new_state_d.rl.revlock[0] << 24) | (new_state_d.rl.revlock[1] >> 8); 
  hash_outputs_preimage[1][7]  = (new_state_d.rl.revlock[1] << 24) | (new_state_d.rl.revlock[2] >> 8);
  hash_outputs_preimage[1][8]  = (new_state_d.rl.revlock[2] << 24) | (new_state_d.rl.revlock[3] >> 8);
  hash_outputs_preimage[1][9]  = (new_state_d.rl.revlock[3] << 24) | (new_state_d.rl.revlock[4] >> 8);
  hash_outputs_preimage[1][10]  = (new_state_d.rl.revlock[4] << 24) | (new_state_d.rl.revlock[5] >> 8);
  hash_outputs_preimage[1][11] = (new_state_d.rl.revlock[5] << 24) | (new_state_d.rl.revlock[6] >> 8);
  hash_outputs_preimage[1][12] = (new_state_d.rl.revlock[6] << 24) | (new_state_d.rl.revlock[7] >> 8);
  hash_outputs_preimage[1][13] = (new_state_d.rl.revlock[7] << 24) | (cust_payout_pub_key_d.key[0] >> 8); //1
  hash_outputs_preimage[1][14] = (cust_payout_pub_key_d.key[0] << 24) | (cust_payout_pub_key_d.key[1] >> 8); //5
  hash_outputs_preimage[1][15] = (cust_payout_pub_key_d.key[1] << 24) | (cust_payout_pub_key_d.key[2] >> 8); //9
  hash_outputs_preimage[2][0] = (cust_payout_pub_key_d.key[2] << 24) | (cust_payout_pub_key_d.key[3] >> 8); //13
  hash_outputs_preimage[2][1]  = (cust_payout_pub_key_d.key[3] << 24) | (cust_payout_pub_key_d.key[4] >> 8); //17
  hash_outputs_preimage[2][2]  = (cust_payout_pub_key_d.key[4] << 24) | (cust_payout_pub_key_d.key[5] >> 8); //21
  hash_outputs_preimage[2][3]  = (cust_payout_pub_key_d.key[5] << 24) | (cust_payout_pub_key_d.key[6] >> 8); //25
  hash_outputs_preimage[2][4]  = (cust_payout_pub_key_d.key[6] << 24) | (cust_payout_pub_key_d.key[7] >> 8); //29
  hash_outputs_preimage[2][5]  = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | Integer(32,32768 /*0x00008000*/, PUBLIC); //33

  hash_outputs_preimage[2][6]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][7]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][8]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][9]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][10] = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][11] = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][12] = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][13] = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][14] = Integer(32, 0, PUBLIC); //0x00000000; 
  hash_outputs_preimage[2][15] = Integer(32, 1200, PUBLIC); 

  computeDoubleSHA256_3d(hash_outputs_preimage, escrow_digest);
}

// make sure new close transactions are well-formed
void validate_transactions_local(State_d new_state_d, 
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, PublicKeyHash_d merch_publickey_hash_d,
  Integer escrow_digest[8]) {

  // 112 bytes --> 896
  Integer customer_delayed_script_hash_preimage[2][16];

  // OPCODE || 1 byte of Rev Lock  0x63a82000  1671962624
  customer_delayed_script_hash_preimage[0][0] = Integer(32, 1671962624 /*0x63a92000*/, PUBLIC) | /* First byte of revlock*/(new_state_d.rl.revlock[0] >> 24);

  // 31 remaining bytes of Rev Lock
  customer_delayed_script_hash_preimage[0][1] = (/* last 3 bytes */ new_state_d.rl.revlock[0] << 8) | ( /* first byte of the next int */ new_state_d.rl.revlock[1] >> 24);
  customer_delayed_script_hash_preimage[0][2] = (new_state_d.rl.revlock[1] << 8) | (new_state_d.rl.revlock[2] >> 24);
  customer_delayed_script_hash_preimage[0][3] = (new_state_d.rl.revlock[2] << 8) | (new_state_d.rl.revlock[3] >> 24);
  customer_delayed_script_hash_preimage[0][4] = (new_state_d.rl.revlock[3] << 8) | (new_state_d.rl.revlock[4] >> 24);
  customer_delayed_script_hash_preimage[0][5] = (new_state_d.rl.revlock[4] << 8) | (new_state_d.rl.revlock[5] >> 24);
  customer_delayed_script_hash_preimage[0][6] = (new_state_d.rl.revlock[5] << 8) | (new_state_d.rl.revlock[6] >> 24);
  customer_delayed_script_hash_preimage[0][7] = (new_state_d.rl.revlock[6] << 8) | (new_state_d.rl.revlock[7] >> 24);
  customer_delayed_script_hash_preimage[0][8] = (new_state_d.rl.revlock[7] << 8) | Integer(32, 136 /*0x00000088*/, PUBLIC);

  customer_delayed_script_hash_preimage[0][9]  = Integer(32, 553648128, PUBLIC) | merch_dispute_key_d.key[0] >> 8; //0x21000000 // taking 3 bytes from the key
  customer_delayed_script_hash_preimage[0][10] = (merch_dispute_key_d.key[0] << 24) | (merch_dispute_key_d.key[1] >> 8); // byte 4-7
  customer_delayed_script_hash_preimage[0][11] = (merch_dispute_key_d.key[1] << 24) | (merch_dispute_key_d.key[2] >> 8); // byte 8-11
  customer_delayed_script_hash_preimage[0][12] = (merch_dispute_key_d.key[2] << 24) | (merch_dispute_key_d.key[3] >> 8); // bytes 12-15
  customer_delayed_script_hash_preimage[0][13] = (merch_dispute_key_d.key[3] << 24) | (merch_dispute_key_d.key[4] >> 8); // bytes 16-19
  customer_delayed_script_hash_preimage[0][14] = (merch_dispute_key_d.key[4] << 24) | (merch_dispute_key_d.key[5] >> 8); // bytes 20-23
  customer_delayed_script_hash_preimage[0][15] = (merch_dispute_key_d.key[5] << 24) | (merch_dispute_key_d.key[6] >> 8); // bytes 24-27
  customer_delayed_script_hash_preimage[1][0]  = (merch_dispute_key_d.key[6] << 24) | (merch_dispute_key_d.key[7] >> 8); // bytes 28-31
  customer_delayed_script_hash_preimage[1][1]  = (merch_dispute_key_d.key[7] << 24) | (merch_dispute_key_d.key[8] >> 8) | Integer(32, 26368/*0x00006700*/, PUBLIC) | Integer(32,2 /*0x000002*/, PUBLIC); // bytes 32-33 // 0x67

  // This previous last byte and the following to bytes is the delay.  We should talk about how long we want them to be
  customer_delayed_script_hash_preimage[1][2]  = Integer(32, 3473211392 /*0xcf050000*/, PUBLIC) | Integer(32, 45685/*0x0000b275*/, PUBLIC);
  customer_delayed_script_hash_preimage[1][3]  = Integer(32, 553648128 /*0x21000000*/, PUBLIC)  | (cust_payout_pub_key_d.key[0] >> 8);
  customer_delayed_script_hash_preimage[1][4]  = (cust_payout_pub_key_d.key[0] << 24) | (cust_payout_pub_key_d.key[1] >> 8);
  customer_delayed_script_hash_preimage[1][5]  = (cust_payout_pub_key_d.key[1] << 24) | (cust_payout_pub_key_d.key[2] >> 8);
  customer_delayed_script_hash_preimage[1][6]  = (cust_payout_pub_key_d.key[2] << 24) | (cust_payout_pub_key_d.key[3] >> 8);
  customer_delayed_script_hash_preimage[1][7]  = (cust_payout_pub_key_d.key[3] << 24) | (cust_payout_pub_key_d.key[4] >> 8);
  customer_delayed_script_hash_preimage[1][8]  = (cust_payout_pub_key_d.key[4] << 24) | (cust_payout_pub_key_d.key[5] >> 8);
  customer_delayed_script_hash_preimage[1][9]  = (cust_payout_pub_key_d.key[5] << 24) | (cust_payout_pub_key_d.key[6] >> 8);
  customer_delayed_script_hash_preimage[1][10] = (cust_payout_pub_key_d.key[6] << 24) | (cust_payout_pub_key_d.key[7] >> 8);
  customer_delayed_script_hash_preimage[1][11] = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | Integer(32, 26796/*0x000068ac*/, PUBLIC);

  customer_delayed_script_hash_preimage[1][12] = Integer(32, -2147483648/*0x80000000*/, PUBLIC); 
  customer_delayed_script_hash_preimage[1][13] = Integer(32, 0, PUBLIC); //0x00000000; 
  customer_delayed_script_hash_preimage[1][14] = Integer(32, 0, PUBLIC); //0x00000000; 
  customer_delayed_script_hash_preimage[1][15] = Integer(32, 896, PUBLIC); 

  Integer customer_delayed_script_hash[8];

  computeSHA256_2d(customer_delayed_script_hash_preimage, customer_delayed_script_hash);

  // 150 bytes
  Integer hash_outputs_preimage[3][16];

  hash_outputs_preimage[0][0]  = new_state_d.balance_cust.balance[0];// first bytes of customer balance // FIX ENDIANNESS
  hash_outputs_preimage[0][1]  = new_state_d.balance_cust.balance[1];// second bytes of customer blanace // FIX ENDIANNESS
  hash_outputs_preimage[0][2]  = Integer(32, 570433536 /*0x22002000*/, PUBLIC) | (customer_delayed_script_hash[0] >> 24); // OPCODE and the first byte of the prev hash output
  hash_outputs_preimage[0][3]  = (customer_delayed_script_hash[0] << 8) | (customer_delayed_script_hash[1] >> 24); // end of byte 1 and first byte of 2...
  hash_outputs_preimage[0][4]  = (customer_delayed_script_hash[1] << 8) | (customer_delayed_script_hash[2] >> 24);
  hash_outputs_preimage[0][5]  = (customer_delayed_script_hash[2] << 8) | (customer_delayed_script_hash[3] >> 24);
  hash_outputs_preimage[0][6]  = (customer_delayed_script_hash[3] << 8) | (customer_delayed_script_hash[4] >> 24);
  hash_outputs_preimage[0][7]  = (customer_delayed_script_hash[4] << 8) | (customer_delayed_script_hash[5] >> 24);
  hash_outputs_preimage[0][8]  = (customer_delayed_script_hash[5] << 8) | (customer_delayed_script_hash[6] >> 24);
  hash_outputs_preimage[0][9]  = (customer_delayed_script_hash[6] << 8) | (customer_delayed_script_hash[7] >> 24);
  hash_outputs_preimage[0][10] = (customer_delayed_script_hash[7] << 8) |  (new_state_d.balance_merch.balance[0] >> 24);/*first byte of merch balance >> 24*/;
  hash_outputs_preimage[0][11] =  (new_state_d.balance_merch.balance[0] << 8) | (new_state_d.balance_merch.balance[1] >> 24);
  hash_outputs_preimage[0][12] =  (new_state_d.balance_merch.balance[1] << 8) | Integer(32, 22 /*0x00000016*/, PUBLIC);
  hash_outputs_preimage[0][13] = Integer(32, 1310720 /*0x00140000*/, PUBLIC) | (merch_publickey_hash_d.hash[0] >> 16);
  hash_outputs_preimage[0][14] = (merch_publickey_hash_d.hash[0] << 16) | (merch_publickey_hash_d.hash[1] >> 16);
  hash_outputs_preimage[0][15] = (merch_publickey_hash_d.hash[1] << 16) | (merch_publickey_hash_d.hash[2] >> 16);
  hash_outputs_preimage[1][0]  = (merch_publickey_hash_d.hash[2] << 16) | (merch_publickey_hash_d.hash[3] >> 16);
  hash_outputs_preimage[1][1]  = (merch_publickey_hash_d.hash[3] << 16) | (merch_publickey_hash_d.hash[4] >> 16);
  hash_outputs_preimage[1][2]  = (merch_publickey_hash_d.hash[4] << 16) | Integer(32, 0 /*0x00000000*/, PUBLIC); //Two bytes of the OP_Return Amount
  hash_outputs_preimage[1][3]  = Integer(32, 0, PUBLIC); // middle 4 bytes of OP_RETURN amount
  hash_outputs_preimage[1][4]  = Integer(32, 17258/*0x0000376a*/,PUBLIC); // OPRETURN FORMATTING 
  hash_outputs_preimage[1][5] = Integer(32, 1090519040/*0x41000000*/,PUBLIC)/*last byte of opreturn formatting */ | (new_state_d.rl.revlock[0] >> 8); 

  hash_outputs_preimage[1][6]  = (new_state_d.rl.revlock[0] << 24) | (new_state_d.rl.revlock[1] >> 8); 
  hash_outputs_preimage[1][7]  = (new_state_d.rl.revlock[1] << 24) | (new_state_d.rl.revlock[2] >> 8);
  hash_outputs_preimage[1][8]  = (new_state_d.rl.revlock[2] << 24) | (new_state_d.rl.revlock[3] >> 8);
  hash_outputs_preimage[1][9]  = (new_state_d.rl.revlock[3] << 24) | (new_state_d.rl.revlock[4] >> 8);
  hash_outputs_preimage[1][10]  = (new_state_d.rl.revlock[4] << 24) | (new_state_d.rl.revlock[5] >> 8);
  hash_outputs_preimage[1][11] = (new_state_d.rl.revlock[5] << 24) | (new_state_d.rl.revlock[6] >> 8);
  hash_outputs_preimage[1][12] = (new_state_d.rl.revlock[6] << 24) | (new_state_d.rl.revlock[7] >> 8);
  hash_outputs_preimage[1][13] = (new_state_d.rl.revlock[7] << 24) | (cust_payout_pub_key_d.key[0] >> 8); //1
  hash_outputs_preimage[1][14] = (cust_payout_pub_key_d.key[0] << 24) | (cust_payout_pub_key_d.key[1] >> 8); //5
  hash_outputs_preimage[1][15] = (cust_payout_pub_key_d.key[1] << 24) | (cust_payout_pub_key_d.key[2] >> 8); //9
  hash_outputs_preimage[2][0] = (cust_payout_pub_key_d.key[2] << 24) | (cust_payout_pub_key_d.key[3] >> 8); //13
  hash_outputs_preimage[2][1]  = (cust_payout_pub_key_d.key[3] << 24) | (cust_payout_pub_key_d.key[4] >> 8); //17
  hash_outputs_preimage[2][2]  = (cust_payout_pub_key_d.key[4] << 24) | (cust_payout_pub_key_d.key[5] >> 8); //21
  hash_outputs_preimage[2][3]  = (cust_payout_pub_key_d.key[5] << 24) | (cust_payout_pub_key_d.key[6] >> 8); //25
  hash_outputs_preimage[2][4]  = (cust_payout_pub_key_d.key[6] << 24) | (cust_payout_pub_key_d.key[7] >> 8); //29
  hash_outputs_preimage[2][5]  = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | Integer(32,32768 /*0x00008000*/, PUBLIC); //33

  hash_outputs_preimage[2][6]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][7]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][8]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][9]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][10] = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][11] = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][12] = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][13] = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][14] = Integer(32, 0, PUBLIC); //0x00000000; 
  hash_outputs_preimage[2][15] = Integer(32, 1200, PUBLIC); 

  Integer hash_outputs[8];

  computeDoubleSHA256_3d(hash_outputs_preimage, hash_outputs);

  // TODO COMPUTE THE DOUBLE HASH

  // The total preimage is 228 bytes
  Integer total_preimage[4][16];

  total_preimage[0][0] = Integer(32, 33554432 /*0x02000000*/, PUBLIC);
  total_preimage[0][1] = new_state_d.HashPrevOuts_escrow.txid[0];
  total_preimage[0][2] = new_state_d.HashPrevOuts_escrow.txid[1];
  total_preimage[0][3] = new_state_d.HashPrevOuts_escrow.txid[2];
  total_preimage[0][4] = new_state_d.HashPrevOuts_escrow.txid[3];
  total_preimage[0][5] = new_state_d.HashPrevOuts_escrow.txid[4];
  total_preimage[0][6] = new_state_d.HashPrevOuts_escrow.txid[5];
  total_preimage[0][7] = new_state_d.HashPrevOuts_escrow.txid[6];
  total_preimage[0][8] = new_state_d.HashPrevOuts_escrow.txid[7];

  total_preimage[0][9]  =  Integer(32, 1001467945  /*0x3bb13029*/, PUBLIC);
  total_preimage[0][10] =  Integer(32, 3464175445 /*0xce7b1f55*/, PUBLIC);
  total_preimage[0][11] =  Integer(32, 2666915655 /*0x9ef5e747*/, PUBLIC);
  total_preimage[0][12] =  Integer(32, 4239147935 /*0xfcac439f*/, PUBLIC);
  total_preimage[0][13] =  Integer(32,  341156588 /*0x1455a2ec*/, PUBLIC);
  total_preimage[0][14] =  Integer(32, 2086603191 /*0x7c5f09b7*/, PUBLIC);
  total_preimage[0][15] =  Integer(32,  579893598 /*0x2290795e*/, PUBLIC);
  total_preimage[1][0]  =  Integer(32, 1885753412  /*0x70665044*/, PUBLIC);

  total_preimage[1][1] = new_state_d.txid_escrow.txid[0];
  total_preimage[1][2] = new_state_d.txid_escrow.txid[1];
  total_preimage[1][3] = new_state_d.txid_escrow.txid[2];
  total_preimage[1][4] = new_state_d.txid_escrow.txid[3];
  total_preimage[1][5] = new_state_d.txid_escrow.txid[4];
  total_preimage[1][6] = new_state_d.txid_escrow.txid[5];
  total_preimage[1][7] = new_state_d.txid_escrow.txid[6];
  total_preimage[1][8] = new_state_d.txid_escrow.txid[7];

  total_preimage[1][9] = Integer(32, 0 , PUBLIC);

  total_preimage[1][10]  = Integer(32, 1196564736/*0x47522100*/, PUBLIC) | (merch_escrow_pub_key_d.key[0] >> 24);
  total_preimage[1][11] = (merch_escrow_pub_key_d.key[0] << 8) | (merch_escrow_pub_key_d.key[1] >> 24);
  total_preimage[1][12] = (merch_escrow_pub_key_d.key[1] << 8) | (merch_escrow_pub_key_d.key[2] >> 24);
  total_preimage[1][13] = (merch_escrow_pub_key_d.key[2] << 8) | (merch_escrow_pub_key_d.key[3] >> 24);
  total_preimage[1][14] = (merch_escrow_pub_key_d.key[3] << 8) | (merch_escrow_pub_key_d.key[4] >> 24);
  total_preimage[1][15] = (merch_escrow_pub_key_d.key[4] << 8) | (merch_escrow_pub_key_d.key[5] >> 24);
  total_preimage[2][0] = (merch_escrow_pub_key_d.key[5] << 8) | (merch_escrow_pub_key_d.key[6] >> 24);
  total_preimage[2][1]  = (merch_escrow_pub_key_d.key[6] << 8) | (merch_escrow_pub_key_d.key[7] >> 24);
  total_preimage[2][2]  = (merch_escrow_pub_key_d.key[7] << 8) | (merch_escrow_pub_key_d.key[8] >> 24);
  total_preimage[2][3]  = Integer(32, 553648128 /*0x21000000*/, PUBLIC) | (cust_escrow_pub_key_d.key[0] >> 8);  // first three bytes of the cust public key
  // 30 more bytes of key
  total_preimage[2][4]  = (cust_escrow_pub_key_d.key[0] << 24)| (cust_escrow_pub_key_d.key[1] >> 8); 
  total_preimage[2][5]  = (cust_escrow_pub_key_d.key[1] << 24)| (cust_escrow_pub_key_d.key[2] >> 8); 
  total_preimage[2][6]  = (cust_escrow_pub_key_d.key[2] << 24)| (cust_escrow_pub_key_d.key[3] >> 8); 
  total_preimage[2][7]  = (cust_escrow_pub_key_d.key[3] << 24)| (cust_escrow_pub_key_d.key[4] >> 8); 
  total_preimage[2][8]  = (cust_escrow_pub_key_d.key[4] << 24)| (cust_escrow_pub_key_d.key[5] >> 8); 
  total_preimage[2][9]  = (cust_escrow_pub_key_d.key[5] << 24)| (cust_escrow_pub_key_d.key[6] >> 8); 
  total_preimage[2][10]  = (cust_escrow_pub_key_d.key[6] << 24)| (cust_escrow_pub_key_d.key[7] >> 8); 
  total_preimage[2][11] = (cust_escrow_pub_key_d.key[7] << 24)| (cust_escrow_pub_key_d.key[8] >> 8) | Integer(32, 21166/*0x000052ae*/, PUBLIC);

  total_preimage[2][12] = Integer(32, 12774155, PUBLIC);//first bytes of input ammount = Balance + Balance // TODO MAKE NOT HARDCODED
  total_preimage[2][13] = Integer(32, 0, PUBLIC);//second bytes of input ammount = Balance + Balance

  total_preimage[2][14] = Integer(32, 4294967295 /*0xffffffff*/, PUBLIC);

  total_preimage[2][15] = hash_outputs[0];
  total_preimage[3][0] = hash_outputs[1];
  total_preimage[3][1] = hash_outputs[2];
  total_preimage[3][2]  = hash_outputs[3];
  total_preimage[3][3]  = hash_outputs[4];
  total_preimage[3][4]  = hash_outputs[5];
  total_preimage[3][5]  = hash_outputs[6];
  total_preimage[3][6]  = hash_outputs[7];

  total_preimage[3][7]  = Integer(32, 0 /*0x00000000*/, PUBLIC);
  total_preimage[3][8]  = Integer(32, 16777216 /*0x01000000*/, PUBLIC);

  total_preimage[3][9]   = Integer(32, -2147483648/*0x80000000*/, PUBLIC); 
  total_preimage[3][10]   = Integer(32, 0, PUBLIC);
  total_preimage[3][11]   = Integer(32, 0, PUBLIC);
  total_preimage[3][12]  = Integer(32, 0, PUBLIC);
  total_preimage[3][13]  = Integer(32, 0, PUBLIC);
  total_preimage[3][14]  = Integer(32, 0, PUBLIC); //0x00000000; 
  total_preimage[3][15]  = Integer(32, 1824, PUBLIC); // 228*8 = 1824 bits

  // Integer escrow_digest[8];
  computeSHA256_4d(total_preimage, escrow_digest);
}

int main(int argc, char** argv) {
  // run in semihonest library
  int port, party;
  if (argc != 3) {
    cerr << "ERROR: not enough args" << endl;
    return 1;
  }
  parse_party_and_port(argv, &party, &port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  // run end-to-end tests
  test_end_to_end();

  delete io;
  return 0;
}
