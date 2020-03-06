#include <typeinfo>
#include "ecdsa.h"
#include "sha256.h"
#include "tokens.h"

using namespace std;

void *io_callback(void *conn, int party) {
    Conn_l *c = (Conn_l *) conn;
    if (c == NULL) return NULL;

    if (c->conn_type == NETIO) {
        NetIO *io = new NetIO((party == MERCH) ? nullptr : "127.0.0.1", 12345);
        return io;
    } else if (c->conn_type == UNIXNETIO) {
        string socket_path = "tmpcon";
        bool is_server = (party == MERCH) ? true : false;
        UnixNetIO *io = new UnixNetIO(socket_path.c_str(), is_server);
        return io;
    }
    return NULL;
}

/* 
 * Test main for token generation
 * generates fake data for now.
 */
int main(int argc, char** argv) {

    if (argc == 2 && strcmp(argv[1], "-m") == 0 ) {
        setup_plain_prot(true, "tokens.circuit.txt");

        HMACKey_l hmac_key_l;
        Mask_l paytoken_mask_l;
        Mask_l merch_mask_l;
        Mask_l escrow_mask_l;
        EcdsaPartialSig_l dummy_sig;

        CommitmentRandomness_l hmac_commitment_randomness_l;
        CommitmentRandomness_l paytoken_mask_commitment_randomness_l;

        State_l old_state_l;
        State_l new_state_l;
        PayToken_l old_paytoken_l;
        BitcoinPublicKey_l cust_escrow_pub_key_l;
        BitcoinPublicKey_l cust_payout_pub_key_l;
        PayToken_l pt_return;
        EcdsaSig_l ct_escrow;
        EcdsaSig_l ct_merch;
        CommitmentRandomness_l revlock_commitment_randomness_l;

        Balance_l epsilon_l;
        RevLockCommitment_l rlc_l;
        MaskCommitment_l paymask_com;
        HMACKeyCommitment_l key_com;
        // int port = 12345;
        BitcoinPublicKey_l merch_escrow_pub_key_l;
        BitcoinPublicKey_l merch_dispute_key_l;
        PublicKeyHash_l merch_publickey_hash;
        BitcoinPublicKey_l merch_payout_pub_key_l;
        Nonce_l nonce_l;

        issue_tokens(/* CUSTOMER INPUTS */
                       old_state_l,
                       new_state_l,
                       old_paytoken_l,
                       cust_escrow_pub_key_l,
                       cust_payout_pub_key_l,
                       revlock_commitment_randomness_l,

                     /* MERCHANT INPUTS */
                       hmac_key_l,
                       paytoken_mask_l,
                       merch_mask_l,
                       escrow_mask_l,
                       dummy_sig,
                       dummy_sig,
                       hmac_commitment_randomness_l,
                       paytoken_mask_commitment_randomness_l,
                     /* TODO: ECDSA Key info */
                     /* PUBLIC INPUTS */
                       epsilon_l,
                       key_com,
                       paymask_com,
                       rlc_l,
                       nonce_l,
                       merch_escrow_pub_key_l,
                       merch_dispute_key_l,
                       merch_payout_pub_key_l,
                       merch_publickey_hash,
                     /* OUTPUTS */
                       &pt_return,
                       &ct_escrow,
                       &ct_merch);
        finalize_plain_prot();
	    return 0;
    }

  assert (argc == 3);
  int party = atoi(argv[1]);
  ConnType conn_type = static_cast<ConnType>(atoi(argv[2]));

  if (conn_type != NETIO && conn_type != UNIXNETIO) {
    cout << "Specified invalid connection type. Options: NETIO(" << NETIO << "), UNIXNETIO(" << UNIXNETIO << ")\n";
    exit(1);
  }

  // Declare shared vars
  char path[32] = "socketconn";
  char ip[32] = "127.0.0.1";
  Conn_l nc;
  nc.conn_type = conn_type;
  nc.path = path;
  nc.dest_ip = ip;
  nc.dest_port = 12345;
  Balance_l amt;
  RevLockCommitment_l rl;
  MaskCommitment_l paymask_com;
  HMACKeyCommitment_l key_com;
  // int port = 12345;
  BitcoinPublicKey_l merch_escrow_pub_key_l;
  BitcoinPublicKey_l merch_dispute_key_l;
  PublicKeyHash_l merch_publickey_hash;
  BitcoinPublicKey_l merch_payout_pub_key_l;
  Nonce_l nonce_l;

  // Initialize shared vars
  amt.balance[0] = 1000;
  amt.balance[1] = 0;
  for(int i=0; i<4; i++) {
	nonce_l.nonce[i] = 0;
  }
  for(int i=0; i<5; i++) {
	merch_publickey_hash.hash[i] = 0;
  }
  for(int i=0; i<8; i++) {
	rl.commitment[i] = 0;
	paymask_com.commitment[i] = 0;
	key_com.commitment[i] = 0;
  }
  for(int i=0; i<9; i++) {
	merch_escrow_pub_key_l.key[i] = 0;
	merch_dispute_key_l.key[i] = 0;
	merch_payout_pub_key_l.key[i] = 0;
  }
  

  // Initialized single-party vars and call functions
  if (party == MERCH) {
	EcdsaPartialSig_l sig;
	string r = "108792476108599305057612221643697785065475034835954270988586688301027220077907";
    string k_inv = "44657876998057202178264530375095959644163723589174927475562391733096641768603";

    fillEcdsaPartialSig_l(&sig, r, k_inv);
    struct HMACKey_l hmac_key;
    struct Mask_l mask;
    CommitmentRandomness_l hmac_rand;
    CommitmentRandomness_l pay_token_rand;

	build_masked_tokens_merch(io_callback, nc,
	  amt, rl, paymask_com, key_com, merch_escrow_pub_key_l,
      merch_dispute_key_l, merch_publickey_hash,
      merch_payout_pub_key_l, nonce_l,
      hmac_key, mask, mask, mask, hmac_rand, pay_token_rand, sig, sig);
  } else {
    State_l w;
    PayToken_l pt_old;
    CommitmentRandomness_l rl_rand;
    BitcoinPublicKey_l cust_escrow_pub_key_l;
    BitcoinPublicKey_l cust_payout_pub_key_l;
    PayToken_l pt_return;
    EcdsaSig_l ct_escrow;
    EcdsaSig_l ct_merch;

    build_masked_tokens_cust(io_callback, nc,
	  amt, rl, paymask_com, key_com, merch_escrow_pub_key_l,
          merch_dispute_key_l, merch_publickey_hash,
          merch_payout_pub_key_l, nonce_l,
	  rl_rand, w, w, pt_old, cust_escrow_pub_key_l, cust_payout_pub_key_l,
	  &pt_return, &ct_escrow, &ct_merch);
  }

  return 0;
}
