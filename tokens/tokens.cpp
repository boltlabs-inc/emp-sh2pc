#include "tokens.h"
#include "tokens-misc.h"
#include "ecdsa.h"
#include "hmac.h"
#include "sha256.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <memory>

#define MERCH ALICE
#define CUST BOB

using namespace emp;

void* get_netio_ptr(char *address, int port, int party) {
    char *address_ptr = (party == MERCH) ? nullptr : address;
    NetIO *io_ptr = new NetIO(address_ptr, port);
    return static_cast<void *>(io_ptr);
}

/* Returns a pointer to a UnixNetIO ptr */
void* get_unixnetio_ptr(char *socket_path, int party) {
    bool is_server = (party == MERCH) ? true : false;
    UnixNetIO *io_ptr = new UnixNetIO(socket_path, is_server);
    return static_cast<void *>(io_ptr);
}

void* get_gonetio_ptr(void *raw_stream_fd, int party) {
    bool is_server = (party == MERCH) ? true : false;
    GoNetIO *io_ptr = new GoNetIO(raw_stream_fd, is_server);
    return static_cast<void *>(io_ptr);
}

// TODO: add more meaningful fail / error states
// TODO: rename to update_state
void issue_tokens(
/* CUSTOMER INPUTS */
  State_l old_state_l,
  State_l new_state_l,
  PayToken_l old_paytoken_l,
  BitcoinPublicKey_l cust_escrow_pub_key_l,
  BitcoinPublicKey_l cust_payout_pub_key_l,
  CommitmentRandomness_l revlock_commitment_randomness_l,
/* MERCHANT INPUTS */
  HMACKey_l hmac_key_l,
  Mask_l paytoken_mask_l,
  Mask_l merch_mask_l,
  Mask_l escrow_mask_l,
  EcdsaPartialSig_l sig1,
  EcdsaPartialSig_l sig2,
  CommitmentRandomness_l hmac_commitment_randomness_l,
  CommitmentRandomness_l paytoken_mask_commitment_randomness_l,

/* TODO: ECDSA Key info */
/* PUBLIC INPUTS */
  Balance_l epsilon_l,
  HMACKeyCommitment_l hmac_key_commitment_l,
  MaskCommitment_l paytoken_mask_commitment_l,
  RevLockCommitment_l rlc_l,
  Nonce_l nonce_l,
  BitcoinPublicKey_l merch_escrow_pub_key_l,
  BitcoinPublicKey_l merch_dispute_key_l, 
  BitcoinPublicKey_l merch_payout_pub_key_l,
  PublicKeyHash_l merch_publickey_hash_l,
/* OUTPUTS */
  PayToken_l* pt_return,
  EcdsaSig_l* ct_escrow,
  EcdsaSig_l* ct_merch
  ) {

  cout << "issuing tokens" << endl;

  State_d old_state_d = distribute_State(old_state_l, CUST);
  State_d new_state_d = distribute_State(new_state_l, CUST);
  PayToken_d old_paytoken_d = distribute_PayToken(old_paytoken_l, CUST);
  BitcoinPublicKey_d cust_escrow_pub_key_d = distribute_BitcoinPublicKey(cust_escrow_pub_key_l, CUST);
  BitcoinPublicKey_d cust_payout_pub_key_d = distribute_BitcoinPublicKey(cust_payout_pub_key_l, CUST);
  CommitmentRandomness_d revlock_commitment_randomness_d = distribute_CommitmentRandomness(revlock_commitment_randomness_l, CUST);


  HMACKey_d hmac_key_d = distribute_HMACKey(hmac_key_l, MERCH);
  Mask_d paytoken_mask_d = distribute_Mask(paytoken_mask_l, MERCH);
  Mask_d merch_mask_d = distribute_Mask(merch_mask_l, MERCH);
  Mask_d escrow_mask_d = distribute_Mask(escrow_mask_l, MERCH);

  CommitmentRandomness_d hmac_commitment_randomness_d = distribute_CommitmentRandomness(hmac_commitment_randomness_l, MERCH);
  CommitmentRandomness_d paytoken_mask_commitment_randomness_d = distribute_CommitmentRandomness(paytoken_mask_commitment_randomness_l, MERCH);

  Balance_d epsilon_d = distribute_Balance(epsilon_l, PUBLIC); // IVE BEEN TREATING THIS LIKE A 32 BIT VALUE, BUT ITS 64
  HMACKeyCommitment_d hmac_key_commitment_d = distribute_HMACKeyCommitment(hmac_key_commitment_l, PUBLIC);
  MaskCommitment_d paytoken_mask_commitment_d = distribute_MaskCommitment(paytoken_mask_commitment_l, PUBLIC);
  RevLockCommitment_d rlc_d = distribute_RevLockCommitment(rlc_l, PUBLIC);
  Nonce_d nonce_d = distribute_Nonce(nonce_l, PUBLIC);
  BitcoinPublicKey_d merch_escrow_pub_key_d = distribute_BitcoinPublicKey(merch_escrow_pub_key_l, PUBLIC);
  BitcoinPublicKey_d merch_dispute_key_d = distribute_BitcoinPublicKey(merch_dispute_key_l, PUBLIC);
  BitcoinPublicKey_d merch_payout_pub_key_d = distribute_BitcoinPublicKey(merch_payout_pub_key_l, PUBLIC);
  PublicKeyHash_d merch_publickey_hash_d = distribute_PublicKeyHash(merch_publickey_hash_l, PUBLIC);


  cout << "distributed everything. verifying token sig" << endl;
  // check old pay token
  Bit error_signal = verify_token_sig(hmac_key_commitment_d, hmac_commitment_randomness_d, hmac_key_d, old_state_d, old_paytoken_d);

  // make sure wallets are well-formed
  // TODO: change name (state, not wallet)
  cout << "comparing wallets" << endl;
  error_signal = (error_signal | compare_wallets(old_state_d, new_state_d, rlc_d, revlock_commitment_randomness_d, nonce_d, epsilon_d));

  // constructs new close transactions and computes hash
  cout << "hashing transactions" << endl;

  Integer escrow_digest[8];
  Integer merch_digest[8];

  validate_transactions(new_state_d, 
    cust_escrow_pub_key_d, cust_payout_pub_key_d,
    merch_escrow_pub_key_d, merch_dispute_key_d, merch_payout_pub_key_d, 
    merch_publickey_hash_d, escrow_digest, merch_digest);

  // we should return into these txserialized_d or hash 

  // sign new close transactions 
  cout << "signing transactions" << endl;
  EcdsaPartialSig_d epsd1 = distribute_EcdsaPartialSig(sig1);
  EcdsaPartialSig_d epsd2 = distribute_EcdsaPartialSig(sig2);

  Integer signed_merch_tx = ecdsa_sign_hashed(merch_digest, epsd1);
  Integer signed_escrow_tx = ecdsa_sign_hashed(escrow_digest, epsd2);

  // sign new pay token
  cout << "signing token" << endl;
  PayToken_d new_paytoken_d = sign_token(new_state_d, hmac_key_d);

  // Transform the signed_merch_tx into the correct format --> array of 8 32bit uints
  EcdsaSig_d signed_merch_tx_parsed;
  EcdsaSig_d signed_escrow_tx_parsed;

  bigint_into_smallint_array(signed_merch_tx_parsed.sig, signed_merch_tx);
  bigint_into_smallint_array(signed_escrow_tx_parsed.sig, signed_escrow_tx);

  // mask pay and close tokens
  cout << "masking pay token" << endl;
  error_signal = ( error_signal | mask_paytoken(new_paytoken_d.paytoken, paytoken_mask_d, paytoken_mask_commitment_d, paytoken_mask_commitment_randomness_d)); // pay token 

  cout << "masking close merch token" << endl;
  mask_closetoken(signed_merch_tx_parsed.sig, merch_mask_d); // close token - merchant close 

  cout << "masking close escrow token" << endl;
  mask_closetoken(signed_escrow_tx_parsed.sig, escrow_mask_d); // close token - escrow close 

  // handle errors
  // If there has been an error, we need to destroy the token values. 
  cout << "handling errors" << endl;
  for(int i=0; i<8; i++) {
    new_paytoken_d.paytoken[i] = handle_error_case(new_paytoken_d.paytoken[i], error_signal);
  }
  for(int i=0; i<8; i++) {
    signed_merch_tx_parsed.sig[i] = handle_error_case(signed_merch_tx_parsed.sig[i], error_signal);
  }
  for(int i=0; i<8; i++) {
    signed_escrow_tx_parsed.sig[i] = handle_error_case(signed_escrow_tx_parsed.sig[i], error_signal);
  }

  localize_PayToken(pt_return, new_paytoken_d, CUST);
  localize_EcdsaSig(ct_escrow, signed_escrow_tx_parsed, CUST);
  localize_EcdsaSig(ct_merch, signed_merch_tx_parsed, CUST);
}

/* customer's token generation function
 *
 * runs MPC to compute masked tokens (close- and pay-).
 * blocks until computation is finished.
 *
 * Assumes close_tx_escrow and close_tx_merch are padded to 
 * exactly 1024 bits according to the SHA256 spec.
 */
void build_masked_tokens_cust(IOCallback io_callback,
  struct Conn_l conn,
  struct Balance_l epsilon_l,
  struct RevLockCommitment_l rlc_l, // TYPISSUE: this doesn't match the docs. should be a commitment

  struct MaskCommitment_l paymask_com,
  struct HMACKeyCommitment_l key_com,
  struct BitcoinPublicKey_l merch_escrow_pub_key_l,
  struct BitcoinPublicKey_l merch_dispute_key_l,
  struct PublicKeyHash_l merch_publickey_hash,
  struct BitcoinPublicKey_l merch_payout_pub_key_l,
  struct Nonce_l nonce_l,

  struct CommitmentRandomness_l revlock_commitment_randomness_l,
  struct State_l w_new,
  struct State_l w_old,
  struct PayToken_l pt_old,
  struct BitcoinPublicKey_l cust_escrow_pub_key_l,
  struct BitcoinPublicKey_l cust_payout_pub_key_l,

  struct PayToken_l* pt_return,
  struct EcdsaSig_l* ct_escrow,
  struct EcdsaSig_l* ct_merch
) {
  // select the IO interface
  UnixNetIO *io1 = nullptr;
  NetIO *io2 = nullptr;
  GoNetIO *io3 = nullptr;
  ConnType conn_type = conn.conn_type;
  if (io_callback != NULL) {
    auto *io_ptr = io_callback((void *) &conn, CUST);
    if (conn_type == UNIXNETIO) {
        io1 = static_cast<UnixNetIO *>(io_ptr);
        setup_semi_honest(io1, CUST);
    } else if (conn_type == NETIO) {
        io2 = static_cast<NetIO *>(io_ptr);
        setup_semi_honest(io2, CUST);
    } else if (conn_type == CUSTOM) {
        io3 = static_cast<GoNetIO *>(io_ptr);
        setup_semi_honest(io3, CUST);
    } else {
        /* custom IO connection */
        cout << "specify a supported connection type" << endl;
        return;
    }
  } else {
    cout << "did not specify a IO connection callback for customer" << endl;
    return;
  }

  // placeholders for vars passed by merchant
  // TODO maybe do all the distributing here, before calling issue_tokens
  HMACKey_l hmac_key_l;
  Mask_l paytoken_mask_l;
  Mask_l merch_mask_l;
  Mask_l escrow_mask_l;
  EcdsaPartialSig_l dummy_sig;

  CommitmentRandomness_l hmac_commitment_randomness_l;
  CommitmentRandomness_l paytoken_mask_commitment_randomness_l;

issue_tokens(
/* CUSTOMER INPUTS */
  w_old,
  w_new,
  pt_old,
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
  pt_return,
  ct_escrow,
  ct_merch
  );

  cout << "customer finished!" << endl;

  if (io1 != nullptr) delete io1;
  if (io2 != nullptr) delete io2;
}

void build_masked_tokens_merch(IOCallback io_callback,
  struct Conn_l conn,
  struct Balance_l epsilon_l,
  struct RevLockCommitment_l rlc_l, // TYPISSUE: this doesn't match the docs. should be a commitment

  struct MaskCommitment_l paymask_com,
  struct HMACKeyCommitment_l key_com,
  struct BitcoinPublicKey_l merch_escrow_pub_key_l,
  struct BitcoinPublicKey_l merch_dispute_key_l,
  struct PublicKeyHash_l merch_publickey_hash,
  struct BitcoinPublicKey_l merch_payout_pub_key_l,
  struct Nonce_l nonce_l,

  struct HMACKey_l hmac_key,
  struct Mask_l merch_mask_l,
  struct Mask_l escrow_mask_l,
  struct Mask_l paytoken_mask_l,
  struct CommitmentRandomness_l hmac_commitment_randomness_l,
  struct CommitmentRandomness_l paytoken_mask_commitment_randomness_l,
  struct EcdsaPartialSig_l sig1,
  struct EcdsaPartialSig_l sig2
) {

  // TODO: switch to smart pointer
  UnixNetIO *io1 = nullptr;
  NetIO *io2 = nullptr;
  GoNetIO *io3 = nullptr;
  ConnType conn_type = conn.conn_type;
  if (io_callback != NULL) {
    auto *io_ptr = io_callback((void *) &conn, MERCH);
    if (conn_type == UNIXNETIO) {
        io1 = static_cast<UnixNetIO *>(io_ptr);
        setup_semi_honest(io1, MERCH);
    } else if (conn_type == NETIO) {
        io2 = static_cast<NetIO *>(io_ptr);
        setup_semi_honest(io2, MERCH);
    } else if (conn_type == CUSTOM) {
        io3 = static_cast<GoNetIO *>(io_ptr);
        setup_semi_honest(io3, MERCH);
    } else {
        /* custom IO connection */
        cout << "specify a supported connection type" << endl;
        return;
    }
  } else {
    cout << "did not specify a IO connection callback for merchant" << endl;
    return;
  }

  State_l old_state_l;
  State_l new_state_l;
  PayToken_l old_paytoken_l;
  BitcoinPublicKey_l cust_escrow_pub_key_l;
  BitcoinPublicKey_l cust_payout_pub_key_l;
  PayToken_l pt_return;
  EcdsaSig_l ct_escrow;
  EcdsaSig_l ct_merch;
  CommitmentRandomness_l revlock_commitment_randomness_l;


issue_tokens(
/* CUSTOMER INPUTS */
  old_state_l,
  new_state_l,
  old_paytoken_l,
  cust_escrow_pub_key_l,
  cust_payout_pub_key_l,
  revlock_commitment_randomness_l,

/* MERCHANT INPUTS */
  hmac_key,
  paytoken_mask_l,
  merch_mask_l,
  escrow_mask_l,
  sig1,
  sig2,
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
  &ct_merch
  );

  cout << "merchant finished!" << endl;

  if (io1 != nullptr) delete io1;
  if (io2 != nullptr) delete io2;
  if (io3 != nullptr) delete io3;
}


Integer makeInteger(bool *bits, int len, int intlen, int party) {
  string bitstr = "";
  for( int i=0; i < len; i++) {
    bitstr += bits[i] ? "1" : "0";
  }
  bitstr = change_base(bitstr,2,10);
  return Integer(intlen, bitstr, party);
}

PayToken_d sign_token(State_d state, HMACKey_d key) {
  PayToken_d paytoken;
  HMACsign(key, state, paytoken.paytoken);
  return paytoken;
}

Bit verify_token_sig(HMACKeyCommitment_d commitment, CommitmentRandomness_d hmac_commitment_randomness_d, HMACKey_d opening, State_d old_state, PayToken_d old_paytoken) {

  // check that the opening is valid 
  Integer message[2][16];

  for(int i=0; i<16; i++) {
    message[0][i] = opening.key[i];
  }

  // Padding
  message[1][0] = hmac_commitment_randomness_d.randomness[0];
  message[1][1] = hmac_commitment_randomness_d.randomness[1];
  message[1][2] = hmac_commitment_randomness_d.randomness[2];
  message[1][3] = hmac_commitment_randomness_d.randomness[3];
  message[1][4] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[1][5] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][6] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][7] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][8] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][9] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][10] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][11] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][12] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][13] = Integer(32, 0, PUBLIC); //0x00000000;

  // Message length 
  message[1][14] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][15] = Integer(32, 640, PUBLIC);

  Integer hashresult[8];

  computeSHA256_2d(message, hashresult);

  Bit b; // TODO initialize to 0

  for(int i=0; i<8; i++) {
     Bit not_equal = !(commitment.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }

  // // Sign the old state again to compare
  PayToken_d recomputed_paytoken;
  HMACsign(opening, old_state, recomputed_paytoken.paytoken);

  for(int i=0; i<8; i++) {
    Bit not_equal = !(recomputed_paytoken.paytoken[i].equal(old_paytoken.paytoken[i]));
    b = b | not_equal;
  }
  return b;
}

// make sure wallets are well-formed
Bit compare_wallets(State_d old_state_d, State_d new_state_d, RevLockCommitment_d rlc_d, CommitmentRandomness_d revlock_commitment_randomness_d, Nonce_d nonce_d, Balance_d epsilon_d) {

  //Make sure the fields are all correct
  Bit b; // TODO initialize to 0

  for(int i=0; i<8; i++) {
     Bit not_equal = !(old_state_d.txid_merch.txid[i].equal(new_state_d.txid_merch.txid[i]));
     b = b | not_equal;
  }

  for(int i=0; i<8; i++) {
     Bit not_equal = !(old_state_d.txid_escrow.txid[i].equal(new_state_d.txid_escrow.txid[i]));
     b = b | not_equal;
  }

  for(int i=0; i<8; i++) {
     Bit not_equal = !(old_state_d.HashPrevOuts_merch.txid[i].equal(new_state_d.HashPrevOuts_merch.txid[i]));
     b = b | not_equal;
  }

  for(int i=0; i<8; i++) {
     Bit not_equal = !(old_state_d.HashPrevOuts_escrow.txid[i].equal(new_state_d.HashPrevOuts_escrow.txid[i]));
     b = b | not_equal;
  }

  // nonce_d has to match the nonce in old state

  b = (b | (!old_state_d.nonce.nonce[0].equal(nonce_d.nonce[0])));
  b = (b | (!old_state_d.nonce.nonce[1].equal(nonce_d.nonce[1])));
  b = (b | (!old_state_d.nonce.nonce[2].equal(nonce_d.nonce[2])));
  b = (b | (!old_state_d.nonce.nonce[3].equal(nonce_d.nonce[3])));

  // check that the rlc is a commitment to the rl in old_state

  // TODO add the randomness to this commitment
  b = (b | verify_revlock_commitment(old_state_d.rl, rlc_d, revlock_commitment_randomness_d));

  Integer epsilon_combined = combine_balance(epsilon_d);
  Integer old_balance_merch_combined = combine_balance(old_state_d.balance_merch);
  Integer old_balance_cust_combined = combine_balance(old_state_d.balance_cust);
  Integer new_balance_merch_combined = combine_balance(new_state_d.balance_merch);
  Integer new_balance_cust_combined = combine_balance(new_state_d.balance_cust);

  // Make sure that balances have been correctly updated
  b = (b | (!new_balance_merch_combined.equal(old_balance_merch_combined + epsilon_combined)));
  b = (b | (!new_balance_cust_combined.equal(old_balance_cust_combined - epsilon_combined)));

  // ZERO CHECK
  // make sure theres enough funds for the amount we have payed
  Integer zero(64, 0, PUBLIC);

  b = (b | (!(old_balance_merch_combined + epsilon_combined).geq(zero)));
  b = (b | (!(old_balance_cust_combined - epsilon_combined).geq(zero)));

  return b;
}

// make sure customer committed to this new wallet
Bit open_commitment() {
  Bit b;
  return b;
}

Bit verify_revlock_commitment(RevLock_d rl_d, RevLockCommitment_d rlc_d, CommitmentRandomness_d rl_rand_d) {
  Bit b;  // TODO initialize to 0

  Integer message[1][16];

  for(int i=0; i<8; i++) {
    message[0][i] = rl_d.revlock[i];
  }

  message[0][8] = rl_rand_d.randomness[0];
  message[0][9] = rl_rand_d.randomness[1];
  message[0][10] = rl_rand_d.randomness[2];
  message[0][11] = rl_rand_d.randomness[3];
  message[0][12] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[0][13] = Integer(32, 0, PUBLIC); //0x00000000;

  // Message length 
  message[0][14] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][15] = Integer(32, 384, PUBLIC); // 256 bit RL

  Integer hashresult[8];

  computeSHA256_1d(message, hashresult);

  for(int i=0; i<8; i++) {
     Bit not_equal = !(rlc_d.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }
  return b;
}

Bit verify_mask_commitment(Mask_d mask, MaskCommitment_d maskcommitment, CommitmentRandomness_d mask_commitment_randomness_d) {
  Bit b;  // TODO initialize to 0

  Integer message[1][16];

  for(int i=0; i<8; i++) {
    message[0][i] = mask.mask[i];
  }

  message[0][8] = mask_commitment_randomness_d.randomness[0];
  message[0][9] = mask_commitment_randomness_d.randomness[1];
  message[0][10] = mask_commitment_randomness_d.randomness[2];
  message[0][11] = mask_commitment_randomness_d.randomness[3];
  message[0][12] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[0][13] = Integer(32, 0, PUBLIC); //0x00000000;

  // Message length 
  message[0][14] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][15] = Integer(32, 384, PUBLIC);

  Integer hashresult[8];

  computeSHA256_1d(message, hashresult);

  for(int i=0; i<8; i++) {
     Bit not_equal = !(maskcommitment.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }
  return b;
}

// make sure new close transactions are well-formed
void validate_transactions(State_d new_state_d, 
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, BitcoinPublicKey_d merch_payout_pub_key_d, 
  PublicKeyHash_d merch_publickey_hash_d, Integer escrow_digest[8], Integer merch_digest[8])
{
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

  // dump_buffer("cust_deplay_script_preimage0=", customer_delayed_script_hash_preimage[0]);
  // dump_buffer("cust_deplay_script_preimage1=", customer_delayed_script_hash_preimage[1]);

  computeSHA256_2d(customer_delayed_script_hash_preimage, customer_delayed_script_hash);

  // 150 bytes
  Integer hash_outputs_preimage[3][16];

  Balance_d little_endian_balance_cust = convert_to_little_endian(new_state_d.balance_cust);
  Balance_d little_endian_balance_merch = convert_to_little_endian(new_state_d.balance_merch);

  hash_outputs_preimage[0][0]  = little_endian_balance_cust.balance[0];// first bytes of customer balance // FIX ENDIANNESS
  hash_outputs_preimage[0][1]  = little_endian_balance_cust.balance[1];// second bytes of customer blanace // FIX ENDIANNESS

  hash_outputs_preimage[0][2]  = Integer(32, 570433536 /*0x22002000*/, PUBLIC) | (customer_delayed_script_hash[0] >> 24); // OPCODE and the first byte of the prev hash output
  hash_outputs_preimage[0][3]  = (customer_delayed_script_hash[0] << 8) | (customer_delayed_script_hash[1] >> 24); // end of byte 1 and first byte of 2...
  hash_outputs_preimage[0][4]  = (customer_delayed_script_hash[1] << 8) | (customer_delayed_script_hash[2] >> 24);
  hash_outputs_preimage[0][5]  = (customer_delayed_script_hash[2] << 8) | (customer_delayed_script_hash[3] >> 24);
  hash_outputs_preimage[0][6]  = (customer_delayed_script_hash[3] << 8) | (customer_delayed_script_hash[4] >> 24);
  hash_outputs_preimage[0][7]  = (customer_delayed_script_hash[4] << 8) | (customer_delayed_script_hash[5] >> 24);
  hash_outputs_preimage[0][8]  = (customer_delayed_script_hash[5] << 8) | (customer_delayed_script_hash[6] >> 24);
  hash_outputs_preimage[0][9]  = (customer_delayed_script_hash[6] << 8) | (customer_delayed_script_hash[7] >> 24);
  hash_outputs_preimage[0][10] = (customer_delayed_script_hash[7] << 8) |  (little_endian_balance_merch.balance[0] >> 24);/*first byte of merch balance >> 24*/;
  hash_outputs_preimage[0][11] =  (little_endian_balance_merch.balance[0] << 8) | (little_endian_balance_merch.balance[1] >> 24);
  hash_outputs_preimage[0][12] =  (little_endian_balance_merch.balance[1] << 8) | Integer(32, 22 /*0x00000016*/, PUBLIC);
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


  // The total preimage is 228 bytes
  Integer total_preimage_escrow[4][16];

  total_preimage_escrow[0][0] = Integer(32, 33554432 /*0x02000000*/, PUBLIC);
  total_preimage_escrow[0][1] = new_state_d.HashPrevOuts_escrow.txid[0];
  total_preimage_escrow[0][2] = new_state_d.HashPrevOuts_escrow.txid[1];
  total_preimage_escrow[0][3] = new_state_d.HashPrevOuts_escrow.txid[2];
  total_preimage_escrow[0][4] = new_state_d.HashPrevOuts_escrow.txid[3];
  total_preimage_escrow[0][5] = new_state_d.HashPrevOuts_escrow.txid[4];
  total_preimage_escrow[0][6] = new_state_d.HashPrevOuts_escrow.txid[5];
  total_preimage_escrow[0][7] = new_state_d.HashPrevOuts_escrow.txid[6];
  total_preimage_escrow[0][8] = new_state_d.HashPrevOuts_escrow.txid[7];

  total_preimage_escrow[0][9]  =  Integer(32, 1001467945  /*0x3bb13029*/, PUBLIC);
  total_preimage_escrow[0][10] =  Integer(32, 3464175445 /*0xce7b1f55*/, PUBLIC);
  total_preimage_escrow[0][11] =  Integer(32, 2666915655 /*0x9ef5e747*/, PUBLIC);
  total_preimage_escrow[0][12] =  Integer(32, 4239147935 /*0xfcac439f*/, PUBLIC);
  total_preimage_escrow[0][13] =  Integer(32,  341156588 /*0x1455a2ec*/, PUBLIC);
  total_preimage_escrow[0][14] =  Integer(32, 2086603191 /*0x7c5f09b7*/, PUBLIC);
  total_preimage_escrow[0][15] =  Integer(32,  579893598 /*0x2290795e*/, PUBLIC);
  total_preimage_escrow[1][0]  =  Integer(32, 1885753412  /*0x70665044*/, PUBLIC);

  total_preimage_escrow[1][1] = new_state_d.txid_escrow.txid[0];
  total_preimage_escrow[1][2] = new_state_d.txid_escrow.txid[1];
  total_preimage_escrow[1][3] = new_state_d.txid_escrow.txid[2];
  total_preimage_escrow[1][4] = new_state_d.txid_escrow.txid[3];
  total_preimage_escrow[1][5] = new_state_d.txid_escrow.txid[4];
  total_preimage_escrow[1][6] = new_state_d.txid_escrow.txid[5];
  total_preimage_escrow[1][7] = new_state_d.txid_escrow.txid[6];
  total_preimage_escrow[1][8] = new_state_d.txid_escrow.txid[7];

  total_preimage_escrow[1][9] = Integer(32, 0 , PUBLIC);

  total_preimage_escrow[1][10]  = Integer(32, 1196564736/*0x47522100*/, PUBLIC) | (merch_escrow_pub_key_d.key[0] >> 24);
  total_preimage_escrow[1][11] = (merch_escrow_pub_key_d.key[0] << 8) | (merch_escrow_pub_key_d.key[1] >> 24);
  total_preimage_escrow[1][12] = (merch_escrow_pub_key_d.key[1] << 8) | (merch_escrow_pub_key_d.key[2] >> 24);
  total_preimage_escrow[1][13] = (merch_escrow_pub_key_d.key[2] << 8) | (merch_escrow_pub_key_d.key[3] >> 24);
  total_preimage_escrow[1][14] = (merch_escrow_pub_key_d.key[3] << 8) | (merch_escrow_pub_key_d.key[4] >> 24);
  total_preimage_escrow[1][15] = (merch_escrow_pub_key_d.key[4] << 8) | (merch_escrow_pub_key_d.key[5] >> 24);
  total_preimage_escrow[2][0] = (merch_escrow_pub_key_d.key[5] << 8) | (merch_escrow_pub_key_d.key[6] >> 24);
  total_preimage_escrow[2][1]  = (merch_escrow_pub_key_d.key[6] << 8) | (merch_escrow_pub_key_d.key[7] >> 24);
  total_preimage_escrow[2][2]  = (merch_escrow_pub_key_d.key[7] << 8) | (merch_escrow_pub_key_d.key[8] >> 24);
  total_preimage_escrow[2][3]  = Integer(32, 553648128 /*0x21000000*/, PUBLIC) | (cust_escrow_pub_key_d.key[0] >> 8);  // first three bytes of the cust public key
  // 30 more bytes of key
  total_preimage_escrow[2][4]  = (cust_escrow_pub_key_d.key[0] << 24)| (cust_escrow_pub_key_d.key[1] >> 8);
  total_preimage_escrow[2][5]  = (cust_escrow_pub_key_d.key[1] << 24)| (cust_escrow_pub_key_d.key[2] >> 8);
  total_preimage_escrow[2][6]  = (cust_escrow_pub_key_d.key[2] << 24)| (cust_escrow_pub_key_d.key[3] >> 8);
  total_preimage_escrow[2][7]  = (cust_escrow_pub_key_d.key[3] << 24)| (cust_escrow_pub_key_d.key[4] >> 8);
  total_preimage_escrow[2][8]  = (cust_escrow_pub_key_d.key[4] << 24)| (cust_escrow_pub_key_d.key[5] >> 8);
  total_preimage_escrow[2][9]  = (cust_escrow_pub_key_d.key[5] << 24)| (cust_escrow_pub_key_d.key[6] >> 8);
  total_preimage_escrow[2][10]  = (cust_escrow_pub_key_d.key[6] << 24)| (cust_escrow_pub_key_d.key[7] >> 8);
  total_preimage_escrow[2][11] = (cust_escrow_pub_key_d.key[7] << 24)| (cust_escrow_pub_key_d.key[8] >> 8) | Integer(32, 21166/*0x000052ae*/, PUBLIC);

  Balance_d big_endian_total_amount = sum_balances(new_state_d.balance_cust, new_state_d.balance_merch);
  Balance_d little_endian_total_amount = convert_to_little_endian(big_endian_total_amount);
  total_preimage_escrow[2][12] = little_endian_total_amount.balance[0];
  total_preimage_escrow[2][13] = little_endian_total_amount.balance[1];

  total_preimage_escrow[2][14] = Integer(32, 4294967295 /*0xffffffff*/, PUBLIC);

  total_preimage_escrow[2][15] = hash_outputs[0];
  total_preimage_escrow[3][0]  = hash_outputs[1];
  total_preimage_escrow[3][1]  = hash_outputs[2];
  total_preimage_escrow[3][2]  = hash_outputs[3];
  total_preimage_escrow[3][3]  = hash_outputs[4];
  total_preimage_escrow[3][4]  = hash_outputs[5];
  total_preimage_escrow[3][5]  = hash_outputs[6];
  total_preimage_escrow[3][6]  = hash_outputs[7];

  total_preimage_escrow[3][7]  = Integer(32, 0 /*0x00000000*/, PUBLIC);
  total_preimage_escrow[3][8]  = Integer(32, 16777216 /*0x01000000*/, PUBLIC);

  total_preimage_escrow[3][9]   = Integer(32, -2147483648/*0x80000000*/, PUBLIC);
  total_preimage_escrow[3][10]  = Integer(32, 0, PUBLIC);
  total_preimage_escrow[3][11]  = Integer(32, 0, PUBLIC);
  total_preimage_escrow[3][12]  = Integer(32, 0, PUBLIC);
  total_preimage_escrow[3][13]  = Integer(32, 0, PUBLIC);
  total_preimage_escrow[3][14]  = Integer(32, 0, PUBLIC); //0x00000000;
  total_preimage_escrow[3][15]  = Integer(32, 1824, PUBLIC); // 228*8 = 1824 bits


  // Integer escrow_digest[8];
  computeDoubleSHA256_4d(total_preimage_escrow, escrow_digest);

    // The total preimage is 228 bytes
  Integer total_preimage_merch[5][16];

  total_preimage_merch[0][0] = Integer(32, 33554432 /*0x02000000*/, PUBLIC);
  total_preimage_merch[0][1] = new_state_d.HashPrevOuts_merch.txid[0];
  total_preimage_merch[0][2] = new_state_d.HashPrevOuts_merch.txid[1];
  total_preimage_merch[0][3] = new_state_d.HashPrevOuts_merch.txid[2];
  total_preimage_merch[0][4] = new_state_d.HashPrevOuts_merch.txid[3];
  total_preimage_merch[0][5] = new_state_d.HashPrevOuts_merch.txid[4];
  total_preimage_merch[0][6] = new_state_d.HashPrevOuts_merch.txid[5];
  total_preimage_merch[0][7] = new_state_d.HashPrevOuts_merch.txid[6];
  total_preimage_merch[0][8] = new_state_d.HashPrevOuts_merch.txid[7];

  total_preimage_merch[0][9]  =  Integer(32, 1001467945  /*0x3bb13029*/, PUBLIC);
  total_preimage_merch[0][10] =  Integer(32, 3464175445 /*0xce7b1f55*/, PUBLIC);
  total_preimage_merch[0][11] =  Integer(32, 2666915655 /*0x9ef5e747*/, PUBLIC);
  total_preimage_merch[0][12] =  Integer(32, 4239147935 /*0xfcac439f*/, PUBLIC);
  total_preimage_merch[0][13] =  Integer(32,  341156588 /*0x1455a2ec*/, PUBLIC);
  total_preimage_merch[0][14] =  Integer(32, 2086603191 /*0x7c5f09b7*/, PUBLIC);
  total_preimage_merch[0][15] =  Integer(32,  579893598 /*0x2290795e*/, PUBLIC);
  total_preimage_merch[1][0]  =  Integer(32, 1885753412  /*0x70665044*/, PUBLIC);

  total_preimage_merch[1][1] = new_state_d.txid_merch.txid[0];
  total_preimage_merch[1][2] = new_state_d.txid_merch.txid[1];
  total_preimage_merch[1][3] = new_state_d.txid_merch.txid[2];
  total_preimage_merch[1][4] = new_state_d.txid_merch.txid[3];
  total_preimage_merch[1][5] = new_state_d.txid_merch.txid[4];
  total_preimage_merch[1][6] = new_state_d.txid_merch.txid[5];
  total_preimage_merch[1][7] = new_state_d.txid_merch.txid[6];
  total_preimage_merch[1][8] = new_state_d.txid_merch.txid[7];

  total_preimage_merch[1][9] = Integer(32, 0 , PUBLIC);

  // The script
  total_preimage_merch[1][10] = Integer(32, 1919111713 /* 0x72635221*/, PUBLIC);

  total_preimage_merch[1][11] = merch_escrow_pub_key_d.key[0];
  total_preimage_merch[1][12] = merch_escrow_pub_key_d.key[1];
  total_preimage_merch[1][13] = merch_escrow_pub_key_d.key[2];
  total_preimage_merch[1][14] = merch_escrow_pub_key_d.key[3];
  total_preimage_merch[1][15] = merch_escrow_pub_key_d.key[4];
  total_preimage_merch[2][0]  = merch_escrow_pub_key_d.key[5];
  total_preimage_merch[2][1]  = merch_escrow_pub_key_d.key[6];
  total_preimage_merch[2][2]  = merch_escrow_pub_key_d.key[7];
  total_preimage_merch[2][3]  = merch_escrow_pub_key_d.key[8] | Integer(32, 2162688 /*0x00210000*/, PUBLIC) | (cust_escrow_pub_key_d.key[0] >> 16);

  // 31 more bytes of key
  total_preimage_merch[2][4]  = (cust_escrow_pub_key_d.key[0] << 16)| (cust_escrow_pub_key_d.key[1] >> 16);
  total_preimage_merch[2][5]  = (cust_escrow_pub_key_d.key[1] << 16)| (cust_escrow_pub_key_d.key[2] >> 16);
  total_preimage_merch[2][6]  = (cust_escrow_pub_key_d.key[2] << 16)| (cust_escrow_pub_key_d.key[3] >> 16);
  total_preimage_merch[2][7]  = (cust_escrow_pub_key_d.key[3] << 16)| (cust_escrow_pub_key_d.key[4] >> 16);
  total_preimage_merch[2][8]  = (cust_escrow_pub_key_d.key[4] << 16)| (cust_escrow_pub_key_d.key[5] >> 16);
  total_preimage_merch[2][9]  = (cust_escrow_pub_key_d.key[5] << 16)| (cust_escrow_pub_key_d.key[6] >> 16);
  total_preimage_merch[2][10] = (cust_escrow_pub_key_d.key[6] << 16)| (cust_escrow_pub_key_d.key[7] >> 16);
  total_preimage_merch[2][11] = (cust_escrow_pub_key_d.key[7] << 16)| (cust_escrow_pub_key_d.key[8] >> 16) | Integer(32, 82/*0x00000052*/, PUBLIC);

  total_preimage_merch[2][12] = Integer(32, 2925986511 /* 0xae6702cf */, PUBLIC);
  total_preimage_merch[2][13] = Integer(32,   95581473 /* 0x05b27521 */, PUBLIC);

  /* merch-payout-key*/
  total_preimage_merch[2][14] = merch_payout_pub_key_d.key[0];
  total_preimage_merch[2][15] = merch_payout_pub_key_d.key[1];
  total_preimage_merch[3][0]  = merch_payout_pub_key_d.key[2];
  total_preimage_merch[3][1]  = merch_payout_pub_key_d.key[3];
  total_preimage_merch[3][2]  = merch_payout_pub_key_d.key[4];
  total_preimage_merch[3][3]  = merch_payout_pub_key_d.key[5];
  total_preimage_merch[3][4]  = merch_payout_pub_key_d.key[6];
  total_preimage_merch[3][5]  = merch_payout_pub_key_d.key[7]; // FIRST 3 bytes of the amount
  total_preimage_merch[3][6]  = merch_payout_pub_key_d.key[8] | Integer(32, 11298816/* 0x00ac6800 */, PUBLIC) | (little_endian_total_amount.balance[0]>>24);

  total_preimage_merch[3][7] = (little_endian_total_amount.balance[0] << 8) | (little_endian_total_amount.balance[1] >> 24);

  total_preimage_merch[3][8] = (little_endian_total_amount.balance[1] << 8) | Integer (32, 255 /* 0x000000ff */ , PUBLIC);
  total_preimage_merch[3][9] = Integer(32, 4294967040 /*0xffffff00*/, PUBLIC) | (hash_outputs[0] >> 24);

  total_preimage_merch[3][10] =  (hash_outputs[0] << 8) | (hash_outputs[1] >> 24);
  total_preimage_merch[3][11] =  (hash_outputs[1] << 8) | (hash_outputs[2] >> 24);
  total_preimage_merch[3][12] =  (hash_outputs[2] << 8) | (hash_outputs[3] >> 24);
  total_preimage_merch[3][13] =  (hash_outputs[3] << 8) | (hash_outputs[4] >> 24);
  total_preimage_merch[3][14] =  (hash_outputs[4] << 8) | (hash_outputs[5] >> 24);
  total_preimage_merch[3][15] =  (hash_outputs[5] << 8) | (hash_outputs[6] >> 24);
  total_preimage_merch[4][0]  =  (hash_outputs[6] << 8) | (hash_outputs[7] >> 24);
  total_preimage_merch[4][1]  =  (hash_outputs[7] << 8) | Integer(32, 0 /*0x00*/, PUBLIC);

  total_preimage_merch[4][2]  = Integer(32, 1 /*0x00000001*/, PUBLIC);
  total_preimage_merch[4][3]  = Integer(32, 128 /*0x00000080*/, PUBLIC);

  total_preimage_merch[4][4]   = Integer(32, 0, PUBLIC);
  total_preimage_merch[4][5]   = Integer(32, 0, PUBLIC);
  total_preimage_merch[4][6]   = Integer(32, 0, PUBLIC);
  total_preimage_merch[4][7]   = Integer(32, 0, PUBLIC);
  total_preimage_merch[4][8]   = Integer(32, 0, PUBLIC);
  total_preimage_merch[4][9]   = Integer(32, 0, PUBLIC);
  total_preimage_merch[4][10]  = Integer(32, 0, PUBLIC);
  total_preimage_merch[4][11]  = Integer(32, 0, PUBLIC);
  total_preimage_merch[4][12]  = Integer(32, 0, PUBLIC);
  total_preimage_merch[4][13]  = Integer(32, 0, PUBLIC);
  total_preimage_merch[4][14]  = Integer(32, 0, PUBLIC);//0x00000000;
  total_preimage_merch[4][15]  = Integer(32, 2168, PUBLIC); // 271*8 = 2168 bits

  computeDoubleSHA256_5d(total_preimage_merch, merch_digest);

  // dump_buffer("hash_outputs_preimage0=", hash_outputs_preimage[0]);
  // dump_buffer("hash_outputs_preimage1=", hash_outputs_preimage[1]);
  // dump_buffer("hash_outputs_preimage2=", hash_outputs_preimage[2]);

  // dump_hash("innermost hash=", customer_delayed_script_hash);

  // dump_buffer("total_preimage_escrow0=", total_preimage_escrow[0]);
  // dump_buffer("total_preimage_escrow1=", total_preimage_escrow[1]);
  // dump_buffer("total_preimage_escrow2=", total_preimage_escrow[2]);
  // dump_buffer("total_preimage_escrow3=", total_preimage_escrow[3]);

  // dump_hash("middle hash=", hash_outputs);

  // dump_buffer("total_preimage_merch0=", total_preimage_merch[0]);
  // dump_buffer("total_preimage_merch1=", total_preimage_merch[1]);
  // dump_buffer("total_preimage_merch2=", total_preimage_merch[2]);
  // dump_buffer("total_preimage_merch3=", total_preimage_merch[3]);
  // dump_buffer("total_preimage_merch4=", total_preimage_merch[4]);
}

// mask pay and close tokens
Bit mask_paytoken(Integer paytoken[8], Mask_d mask, MaskCommitment_d maskcommitment, CommitmentRandomness_d paytoken_mask_commitment_randomness_d) {

  // The pay token is 256 bits long.
  // Thus the mask is 256 bits long.
  // First we check to see if the mask was correct

  Bit b = verify_mask_commitment(mask, maskcommitment, paytoken_mask_commitment_randomness_d);

  for(int i=0; i<8; i++) {
    paytoken[i] = paytoken[i] ^ mask.mask[i];
  }

  return b;
}

// applies a mask to a 256-bit token (made of 8x32-bit integers)
void mask_closetoken(Integer token[8], Mask_d mask) {
  for(int i=0; i<8; i++) {
    token[i] = token[i] ^ mask.mask[i];
  }
}
