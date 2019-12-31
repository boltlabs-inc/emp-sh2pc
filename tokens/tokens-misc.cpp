#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens-misc.h"
#include "sha256.h"

HMACKey_d distribute_HMACKey(HMACKey_l key, const int party) {

  HMACKey_d to_return;

  to_return.key[0] = Integer(32, key.key[0], party);
  to_return.key[1] = Integer(32, key.key[1], party);
  to_return.key[2] = Integer(32, key.key[2], party);
  to_return.key[3] = Integer(32, key.key[3], party);
  to_return.key[4] = Integer(32, key.key[4], party);
  to_return.key[5] = Integer(32, key.key[5], party);
  to_return.key[6] = Integer(32, key.key[6], party);
  to_return.key[7] = Integer(32, key.key[7], party);
  to_return.key[8] = Integer(32, key.key[8], party);
  to_return.key[9] = Integer(32, key.key[9], party);
  to_return.key[10] = Integer(32, key.key[10], party);
  to_return.key[11] = Integer(32, key.key[11], party);
  to_return.key[12] = Integer(32, key.key[12], party);
  to_return.key[13] = Integer(32, key.key[13], party);
  to_return.key[14] = Integer(32, key.key[14], party);
  to_return.key[15] = Integer(32, key.key[15], party);

  return to_return;
}

HMACKey_l localize_HMACKey(HMACKey_d key, const int party) {
  HMACKey_l to_return;
  // GABE TODO
  
  return to_return;
}

RevLockCommitment_d distribute_RevLockCommitment(RevLockCommitment_l rlc, const int party) {
  RevLockCommitment_d to_return;

  to_return.commitment[0] = Integer(32, rlc.commitment[0], party, true);
  to_return.commitment[1] = Integer(32, rlc.commitment[1], party, true);
  to_return.commitment[2] = Integer(32, rlc.commitment[2], party, true);
  to_return.commitment[3] = Integer(32, rlc.commitment[3], party, true);
  to_return.commitment[4] = Integer(32, rlc.commitment[4], party, true);
  to_return.commitment[5] = Integer(32, rlc.commitment[5], party, true);
  to_return.commitment[6] = Integer(32, rlc.commitment[6], party, true);
  to_return.commitment[7] = Integer(32, rlc.commitment[7], party, true);

  return to_return;
}

RevLockCommitment_l localize_RevLockCommitment(RevLockCommitment_d rlc, const int party) {
  RevLockCommitment_l to_return;
  return to_return;
}

RevLock_d distribute_RevLock(RevLock_l revlock, const int party) {

  RevLock_d to_return;

  to_return.revlock[0] = Integer(32, revlock.revlock[0], party);
  to_return.revlock[1] = Integer(32, revlock.revlock[1], party);
  to_return.revlock[2] = Integer(32, revlock.revlock[2], party);
  to_return.revlock[3] = Integer(32, revlock.revlock[3], party);
  to_return.revlock[4] = Integer(32, revlock.revlock[4], party);
  to_return.revlock[5] = Integer(32, revlock.revlock[5], party);
  to_return.revlock[6] = Integer(32, revlock.revlock[6], party);
  to_return.revlock[7] = Integer(32, revlock.revlock[7], party);

  return to_return;
}

RevLock_l localize_RevLock(RevLock_d revlock, const int party) {
  RevLock_l to_return;
  // GABE TODO

  return to_return;
}

PayToken_d distribute_PayToken(PayToken_l paytoken, const int party) {

  PayToken_d to_return;

  to_return.paytoken[0] = Integer(32, paytoken.paytoken[0], party);
  to_return.paytoken[1] = Integer(32, paytoken.paytoken[1], party);
  to_return.paytoken[2] = Integer(32, paytoken.paytoken[2], party);
  to_return.paytoken[3] = Integer(32, paytoken.paytoken[3], party);
  to_return.paytoken[4] = Integer(32, paytoken.paytoken[4], party);
  to_return.paytoken[5] = Integer(32, paytoken.paytoken[5], party);
  to_return.paytoken[6] = Integer(32, paytoken.paytoken[6], party);
  to_return.paytoken[7] = Integer(32, paytoken.paytoken[7], party);

  return to_return;
}

void localize_PayToken(PayToken_l* target, PayToken_d paytoken, const int party) {  
  for(int i=0; i<8; i++) {
    target->paytoken[i] = paytoken.paytoken[i].reveal<uint32_t>(party);
  }
}

Nonce_d distribute_Nonce(Nonce_l nonce, const int party)  {

  Nonce_d to_return;

  to_return.nonce[0] = Integer(32, nonce.nonce[0], party, true);
  to_return.nonce[1] = Integer(32, nonce.nonce[1], party, true);
  to_return.nonce[2] = Integer(32, nonce.nonce[2], party, true);
  to_return.nonce[3] = Integer(32, nonce.nonce[3], party, true);

  return to_return;
}

Nonce_l localize_Nonce(Nonce_d nonce, const int party) {
  Nonce_l to_return;
  // GABE TODO

  return to_return;
}

Txid_d distribute_Txid(Txid_l txid, const int party) {

  Txid_d to_return;

  to_return.txid[0] = Integer(32, txid.txid[0], party);
  to_return.txid[1] = Integer(32, txid.txid[1], party);
  to_return.txid[2] = Integer(32, txid.txid[2], party);
  to_return.txid[3] = Integer(32, txid.txid[3], party);
  to_return.txid[4] = Integer(32, txid.txid[4], party);
  to_return.txid[5] = Integer(32, txid.txid[5], party);
  to_return.txid[6] = Integer(32, txid.txid[6], party);
  to_return.txid[7] = Integer(32, txid.txid[7], party);

  return to_return;  
}

Txid_l localize_Txid(Txid_d txid, const int party) {
  Txid_l to_return;

  return to_return;
}

State_d distribute_State(State_l state, const int party) {

  State_d to_return;

  to_return.nonce = distribute_Nonce(state.nonce, party);
  to_return.rl = distribute_RevLock(state.rl, party);

  to_return.balance_cust = distribute_Balance(state.balance_cust, party);
  to_return.balance_merch = distribute_Balance(state.balance_merch, party);

  to_return.txid_merch = distribute_Txid(state.txid_merch, party);
  to_return.txid_escrow = distribute_Txid(state.txid_escrow, party);

  to_return.HashPrevOuts_merch = distribute_Txid(state.HashPrevOuts_merch, party);
  to_return.HashPrevOuts_escrow = distribute_Txid(state.HashPrevOuts_escrow, party);

  return to_return;
}

State_l localize_State(State_d state, const int party){
  State_l to_return;
  // GABE TODO

  return to_return;
}

HMACKeyCommitment_d distribute_HMACKeyCommitment(HMACKeyCommitment_l commitment, const int party) {

  HMACKeyCommitment_d to_return;

  to_return.commitment[0] = Integer(32, commitment.commitment[0], party, true);
  to_return.commitment[1] = Integer(32, commitment.commitment[1], party, true);
  to_return.commitment[2] = Integer(32, commitment.commitment[2], party, true);
  to_return.commitment[3] = Integer(32, commitment.commitment[3], party, true);
  to_return.commitment[4] = Integer(32, commitment.commitment[4], party, true);
  to_return.commitment[5] = Integer(32, commitment.commitment[5], party, true);
  to_return.commitment[6] = Integer(32, commitment.commitment[6], party, true);
  to_return.commitment[7] = Integer(32, commitment.commitment[7], party, true);

  return to_return;  

}

HMACKeyCommitment_l localize_HMACKeyCommitment(HMACKeyCommitment_d commitment, const int party) {
  HMACKeyCommitment_l to_return;
  // GABE TODO

  return to_return;
}

MaskCommitment_d distribute_MaskCommitment(MaskCommitment_l commitment, const int party) {

  MaskCommitment_d to_return;

  to_return.commitment[0] = Integer(32, commitment.commitment[0], party, true);
  to_return.commitment[1] = Integer(32, commitment.commitment[1], party, true);
  to_return.commitment[2] = Integer(32, commitment.commitment[2], party, true);
  to_return.commitment[3] = Integer(32, commitment.commitment[3], party, true);
  to_return.commitment[4] = Integer(32, commitment.commitment[4], party, true);
  to_return.commitment[5] = Integer(32, commitment.commitment[5], party, true);
  to_return.commitment[6] = Integer(32, commitment.commitment[6], party, true);
  to_return.commitment[7] = Integer(32, commitment.commitment[7], party, true);

  return to_return;  

}

MaskCommitment_l localize_MaskCommitment(MaskCommitment_d commitment, const int party) {
  MaskCommitment_l to_return;
  // GABE TODO

  return to_return;
}

PublicKeyHash_d distribute_PublicKeyHash(PublicKeyHash_l hash, const int party) {
  PublicKeyHash_d to_return;

  to_return.hash[0] = Integer(32, hash.hash[0], party, true);
  to_return.hash[1] = Integer(32, hash.hash[1], party, true);
  to_return.hash[2] = Integer(32, hash.hash[2], party, true);
  to_return.hash[3] = Integer(32, hash.hash[3], party, true);
  to_return.hash[4] = Integer(32, hash.hash[4], party, true);

  return to_return;
}

PublicKeyHash_l localize_PublicKeyHash(PublicKeyHash_d hash, const int party) {
  PublicKeyHash_l to_return;

  return to_return;
}

Balance_d distribute_Balance(Balance_l balance, const int party) {
  Balance_d to_return;

  // validate public inputs
  to_return.balance[0] = Integer(32, balance.balance[0], party, true);
  to_return.balance[1] = Integer(32, balance.balance[1], party, true);

  return to_return;
}

Balance_l localize_Balance(Balance_d balance, const int party) {
  Balance_l to_return;

  return to_return;
}

Mask_d distribute_Mask(Mask_l mask, const int party) {

  Mask_d to_return;

  to_return.mask[0] = Integer(32, mask.mask[0], party);
  to_return.mask[1] = Integer(32, mask.mask[1], party);
  to_return.mask[2] = Integer(32, mask.mask[2], party);
  to_return.mask[3] = Integer(32, mask.mask[3], party);
  to_return.mask[4] = Integer(32, mask.mask[4], party);
  to_return.mask[5] = Integer(32, mask.mask[5], party);
  to_return.mask[6] = Integer(32, mask.mask[6], party);
  to_return.mask[7] = Integer(32, mask.mask[7], party);

  return to_return;  
}

Mask_l localize_Mask(Mask_d mask, const int party) {
  Mask_l to_return;
  // GABE TODO

  return to_return;
}

BitcoinPublicKey_d distribute_BitcoinPublicKey(BitcoinPublicKey_l pubKey, const int party) {

  BitcoinPublicKey_d to_return;

  to_return.key[0] = Integer(32, pubKey.key[0], party, true);
  to_return.key[1] = Integer(32, pubKey.key[1], party, true);
  to_return.key[2] = Integer(32, pubKey.key[2], party, true);
  to_return.key[3] = Integer(32, pubKey.key[3], party, true);
  to_return.key[4] = Integer(32, pubKey.key[4], party, true);
  to_return.key[5] = Integer(32, pubKey.key[5], party, true);
  to_return.key[6] = Integer(32, pubKey.key[6], party, true);
  to_return.key[7] = Integer(32, pubKey.key[7], party, true);
  to_return.key[8] = Integer(32, pubKey.key[8], party, true);

  return to_return;
}

BitcoinPublicKey_l localize_BitcoinPublicKey(BitcoinPublicKey_d pubKey, const int party) {
  BitcoinPublicKey_l to_return;

  return to_return;
}


// constructor that converts strings to mutable char *s (per rust req)
void fillEcdsaPartialSig_l(EcdsaPartialSig_l *eps, string r, string k_inv) {
  for (uint i=0; i < 256; i++) {
    if (i < r.length()) {
      eps->r[i] = r[i];
    } else {
      eps->r[i] = '\0';
    }

    if (i < k_inv.length()) {
      eps->k_inv[i] = k_inv[i];
    } else {
      eps->k_inv[i] = '\0';
    }
  }
}

EcdsaPartialSig_d distribute_EcdsaPartialSig(EcdsaPartialSig_l psl, const int party){
  EcdsaPartialSig_d to_return;
  string r(psl.r);
  to_return.r = Integer(258, r, party);
  string kinv(psl.k_inv);

  to_return.k_inv = Integer(516, kinv, party);
  to_return.k_inv = to_return.k_inv;

  return to_return;
}

// honestly, if we ever need to do this (which we shouldn't outside of testing)
// we definitely should not reveal them publicly.
EcdsaPartialSig_l localize_EcdsaPartialSig(EcdsaPartialSig_d psd, const int party){
  EcdsaPartialSig_l to_return;

  string r = psd.r.reveal<string>(party);
  string k_inv = psd.k_inv.reveal<string>(party);
  fillEcdsaPartialSig_l(&to_return, r, k_inv);

  return to_return;
}

EcdsaSig_d distribute_EcdsaSig(EcdsaSig_l EcdsaSig, const int party) {
  EcdsaSig_d to_return;

  to_return.sig[0] = Integer(32, EcdsaSig.sig[0], party);
  to_return.sig[1] = Integer(32, EcdsaSig.sig[1], party);
  to_return.sig[2] = Integer(32, EcdsaSig.sig[2], party);
  to_return.sig[3] = Integer(32, EcdsaSig.sig[3], party);
  to_return.sig[4] = Integer(32, EcdsaSig.sig[4], party);
  to_return.sig[5] = Integer(32, EcdsaSig.sig[5], party);
  to_return.sig[6] = Integer(32, EcdsaSig.sig[6], party);
  to_return.sig[7] = Integer(32, EcdsaSig.sig[7], party);

  return to_return;
}

void localize_EcdsaSig(EcdsaSig_l* target, EcdsaSig_d EcdsaSig, const int party) {
  for(int i=0; i<8; i++) {
    target->sig[i] = EcdsaSig.sig[i].reveal<uint32_t>(party);
  }
}


Balance_d convert_to_little_endian(Balance_d big_endian_balance) {
  Balance_d little_endian_balance;

  Integer mask_second_leftmost_byte(32, 16711680 /* 00ff0000 */, PUBLIC);
  Integer mask_second_rightmost_byte(32, 65280 /* 0000ff00 */, PUBLIC);

  little_endian_balance.balance[0] = ((big_endian_balance.balance[1]) << 24)
        | ((big_endian_balance.balance[1] & mask_second_rightmost_byte) << 8)
        | ((big_endian_balance.balance[1] & mask_second_leftmost_byte) >> 8)
        | ((big_endian_balance.balance[1]) >> 24);

  little_endian_balance.balance[1] = ((big_endian_balance.balance[0]) << 24)
        | ((big_endian_balance.balance[0] & mask_second_rightmost_byte) << 8)
        | ((big_endian_balance.balance[0] & mask_second_leftmost_byte) >> 8)
        | ((big_endian_balance.balance[0]) >> 24);

  return little_endian_balance;

}
Balance_d convert_to_big_endian(Balance_d little_endian_balance) {
  Balance_d big_endian_balance;

  Integer mask_second_leftmost_byte(32, 16711680 /* 00ff0000 */, PUBLIC);
  Integer mask_second_rightmost_byte(32, 65280 /* 0000ff00 */, PUBLIC);

  big_endian_balance.balance[0] = ((little_endian_balance.balance[1]) << 24)
        | ((little_endian_balance.balance[1] & mask_second_rightmost_byte) << 8)
        | ((little_endian_balance.balance[1] & mask_second_leftmost_byte) >> 8)
        | ((little_endian_balance.balance[1]) >> 24);

  big_endian_balance.balance[1] = ((little_endian_balance.balance[0]) << 24)
        | ((little_endian_balance.balance[0] & mask_second_rightmost_byte) << 8)
        | ((little_endian_balance.balance[0] & mask_second_leftmost_byte) >> 8)
        | ((little_endian_balance.balance[0]) >> 24);

  return big_endian_balance;
}

Balance_d sum_balances(Balance_d lhs, Balance_d rhs) {
  Balance_d to_return;

  Integer result(64, 0, PUBLIC);

  lhs.balance[0].resize(64, true);
  lhs.balance[1].resize(64, true);

  Integer lhs_composed = lhs.balance[1];
  lhs_composed = (lhs_composed<<32) | lhs.balance[0];

  rhs.balance[0].resize(64, true);
  rhs.balance[1].resize(64, true);

  Integer rhs_composed = rhs.balance[1];
  rhs_composed = (rhs_composed<<32) | rhs.balance[0];

  result = rhs_composed + lhs_composed;
  Integer result_dup(result);

  to_return.balance[0] = result.resize(32);
  to_return.balance[1] = (result_dup>>32).resize(32);

  return to_return;
}

Integer handle_error_case(Integer data, Bit mask) {
  Integer to_return = data;

  for(int i=0; i<data.size(); i++) {
    to_return[i] = data[i] | mask;
  }

  return to_return;
}

void bigint_into_smallint_array(Integer target[8], Integer source) {
  Integer mask(256, 4294967295 /* 0xffffffff */, PUBLIC);

  target[7] = mask & source;
  target[7] = target[7].resize(32);

  mask = mask << 32;
  target[6] = mask & source;
  target[6] = target[6] >> 32;
  target[6] = target[6].resize(32);

  mask = mask << 32;
  target[5] = mask & source;
  target[5] = target[5] >> 64;
  target[5] = target[5].resize(32);

  mask = mask << 32;
  target[4] = mask & source;
  target[4] = target[4] >> 96;
  target[4] = target[4].resize(32);

  mask = mask << 32;
  target[3] = mask & source;
  target[3] = target[3] >> 128;
  target[3] = target[3].resize(32);

  mask = mask << 32;
  target[2] = mask & source;
  target[2] = target[2] >> 160;
  target[2] = target[2].resize(32);

  mask = mask << 32;
  target[1] = mask & source;
  target[1] = target[1] >> 192;
  target[1] = target[1].resize(32);

  mask = mask << 32;
  target[0] = mask & source;
  target[0] = target[0] >> 224;
  target[0] = target[0].resize(32);
}

Integer combine_balance(Balance_d balance) {
  balance.balance[0].resize(64);
  balance.balance[1].resize(64);
  balance.balance[0] = balance.balance[0] << 32;
  return balance.balance[0] | balance.balance[1];
}


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

void dump_buffer(string label, Integer buffer[16]) {
  Integer temp = compose_buffer(buffer);

  string temp_string = temp.reveal_unsigned(PUBLIC,16);
  std::cout << label << temp_string  << std::endl;
}

void dump_hash(string label, Integer buffer[8]) {
  Integer temp = composeSHA256result(buffer);

  string temp_string = temp.reveal_unsigned(PUBLIC,16);
  std::cout << label << temp_string  << std::endl;
}


void dump_bit(string label, Bit b) {
  string temp_string = b.reveal<string>(PUBLIC);
  std::cout << label << temp_string  << std::endl;
}
