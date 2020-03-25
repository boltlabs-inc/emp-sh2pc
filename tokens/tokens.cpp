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

Integer xsixthreedot;
Integer eighteight;
Integer xtwentyone;
Integer sixsevenzero;
Integer twohundred;
Integer xcfzerofive;
Integer btwosevenfive;
Integer eightninesix;
Integer sixeightac;
Integer xtwentytwodot;
Integer sixteen;
Integer xzerozerofourteen;
Integer threesevensixa;
Integer xfourtyone;
Integer eightthousand;
Integer twelvehundred;
Integer xzerotwo;
Integer xthreedot;
Integer xcdot;
Integer xninedot;
Integer xfdot;
Integer xfourteendot;
Integer xsevendot;
Integer xtwentytwoninedot;
Integer xsevenzerosixdot ;
Integer xfoursevenfivedot;
Integer fivetwoae;
Integer fullFthirtytwo;
Integer xzeroone;
Integer oneeighttwofour; // 228*8 = 1824 bits
Integer xseventwosixdot;
Integer xzerozerotwentyone;
Integer fiftytwo;
Integer xaedot;
Integer xzerofivedot;
Integer acsixeightzerozero;
Integer ff;
Integer ffffffzerozero;
Integer one;
Integer eighty;
Integer twoonesixeight; // 271*8 = 2168 bits
Integer xzerozeroff;
Integer ffzerozero;
Integer thirtytwo;

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
#if defined(DEBUG)
  cout << "issuing tokens" << endl;
#endif

  State_d old_state_d = distribute_State(old_state_l, CUST);
  State_d new_state_d = distribute_State(new_state_l, CUST);
  PayToken_d old_paytoken_d = distribute_PayToken(old_paytoken_l, CUST);
  BitcoinPublicKey_d cust_escrow_pub_key_d = distribute_BitcoinPublicKey(cust_escrow_pub_key_l, CUST);
  BitcoinPublicKey_d cust_payout_pub_key_d = distribute_BitcoinPublicKey(cust_payout_pub_key_l, CUST);
  CommitmentRandomness_d revlock_commitment_randomness_d = distribute_CommitmentRandomness(revlock_commitment_randomness_l, CUST);

  // PUBLIC values
  Balance_d epsilon_d = distribute_Balance(epsilon_l, CUST); // IVE BEEN TREATING THIS LIKE A 32 BIT VALUE, BUT ITS 64
  HMACKeyCommitment_d hmac_key_commitment_d = distribute_HMACKeyCommitment(hmac_key_commitment_l, CUST);
  MaskCommitment_d paytoken_mask_commitment_d = distribute_MaskCommitment(paytoken_mask_commitment_l, CUST);
  RevLockCommitment_d rlc_d = distribute_RevLockCommitment(rlc_l, CUST);
  Nonce_d nonce_d = distribute_Nonce(nonce_l, CUST);
  BitcoinPublicKey_d merch_escrow_pub_key_d = distribute_BitcoinPublicKey(merch_escrow_pub_key_l, CUST);
  BitcoinPublicKey_d merch_dispute_key_d = distribute_BitcoinPublicKey(merch_dispute_key_l, CUST);
  BitcoinPublicKey_d merch_payout_pub_key_d = distribute_BitcoinPublicKey(merch_payout_pub_key_l, CUST);
  PublicKeyHash_d merch_publickey_hash_d = distribute_PublicKeyHash(merch_publickey_hash_l, CUST);
  //Hardcoded values
  Integer ipad(32, 909522486, CUST);
  Integer xeight(32, -2147483648, CUST); //0x80000000;
  Integer threeazero(32, 2048, CUST); //0x000003a0;
  Integer opad(32, 1549556828, CUST);
  Integer threehundred(32, 768, CUST); //0x00000300;
  Integer sixforty(32, 640, CUST);
  Integer fullF(256, 4294967295 /* 0xffffffff */, CUST);
  Integer twofivesix(32, 256, CUST);
  Integer threeeightfour(32, 384, CUST);

  Integer k[64];
  Integer H[8];
  initSHA256(k, H, CUST);

  xsixthreedot = Integer(32, 1671962624 /*0x63a92000*/, CUST);
  eighteight = Integer(32, 136 /*0x00000088*/, CUST);
  xtwentyone = Integer(32, 553648128, CUST);
  sixsevenzero = Integer(32, 26368/*0x00006700*/, CUST);
  twohundred = Integer(32,2 /*0x000002*/, CUST);
  xcfzerofive = Integer(32, 3473211392 /*0xcf050000*/, CUST);
  btwosevenfive = Integer(32, 45685/*0x0000b275*/, CUST);
  eightninesix = Integer(32, 896, CUST);
  sixeightac = Integer(32, 26796/*0x000068ac*/, CUST);
  xtwentytwodot = Integer(32, 570433536 /*0x22002000*/, CUST);
  sixteen = Integer(32, 22 /*0x00000016*/, CUST);
  xzerozerofourteen = Integer(32, 1310720 /*0x00140000*/, CUST);
  threesevensixa = Integer(32, 17258/*0x0000376a*/, CUST);
  xfourtyone = Integer(32, 1090519040/*0x41000000*/, CUST);
  eightthousand = Integer(32,32768 /*0x00008000*/, CUST);
  twelvehundred = Integer(32, 1200, CUST);
  xzerotwo = Integer(32, 33554432 /*0x02000000*/, CUST);
  xthreedot = Integer(32, 1001467945  /*0x3bb13029*/, CUST);
  xcdot = Integer(32, 3464175445 /*0xce7b1f55*/, CUST);
  xninedot = Integer(32, 2666915655 /*0x9ef5e747*/, CUST);
  xfdot = Integer(32, 4239147935 /*0xfcac439f*/, CUST);
  xfourteendot = Integer(32,  341156588 /*0x1455a2ec*/, CUST);
  xsevendot = Integer(32, 2086603191 /*0x7c5f09b7*/, CUST);
  xtwentytwoninedot = Integer(32,  579893598 /*0x2290795e*/, CUST);
  xsevenzerosixdot  = Integer(32, 1885753412  /*0x70665044*/, CUST);
  xfoursevenfivedot = Integer(32, 1196564736/*0x47522100*/, CUST);
  fivetwoae = Integer(32, 21166/*0x000052ae*/, CUST);
  fullFthirtytwo = Integer(32, 4294967295 /*0xffffffff*/, CUST);
  xzeroone = Integer(32, 16777216 /*0x01000000*/, CUST);
  oneeighttwofour = Integer(32, 1824, CUST); // 228*8 = 1824 bits
  xseventwosixdot = Integer(32, 1919111713 /* 0x72635221*/, CUST);
  xzerozerotwentyone = Integer(32, 2162688 /*0x00210000*/, CUST);
  fiftytwo = Integer(32, 82/*0x00000052*/, CUST);
  xaedot = Integer(32, 2925986511 /* 0xae6702cf */, CUST);
  xzerofivedot = Integer(32,   95581473 /* 0x05b27521 */, CUST);
  acsixeightzerozero = Integer(32, 11298816/* 0x00ac6800 */, CUST);
  ff = Integer(32, 255 /* 0x000000ff */ , CUST);
  ffffffzerozero = Integer(32, 4294967040 /*0xffffff00*/, CUST);
  one = Integer(32, 1 /*0x00000001*/, CUST);
  eighty = Integer(32, 128 /*0x00000080*/, CUST);
  twoonesixeight = Integer(32, 2168, CUST); // 271*8 = 2168 bits

  xzerozeroff = Integer(32, 16711680 /* 00ff0000 */, CUST);
  ffzerozero = Integer(32, 65280 /* 0000ff00 */, CUST);
  thirtytwo = Integer(256, 32, CUST);

  string q2str = "57896044618658097711785492504343953926418782139537452191302581570759080747169";
  Integer q2(516, q2str, CUST);
  string qstr = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
  Integer q(258, qstr, CUST);

  Integer zero(32, 0, CUST);

  //MERCH input
  HMACKey_d hmac_key_d = distribute_HMACKey(hmac_key_l, MERCH);
  Mask_d paytoken_mask_d = distribute_Mask(paytoken_mask_l, MERCH);
  Mask_d merch_mask_d = distribute_Mask(merch_mask_l, MERCH);
  Mask_d escrow_mask_d = distribute_Mask(escrow_mask_l, MERCH);

  CommitmentRandomness_d hmac_commitment_randomness_d = distribute_CommitmentRandomness(hmac_commitment_randomness_l, MERCH);
  CommitmentRandomness_d paytoken_mask_commitment_randomness_d = distribute_CommitmentRandomness(paytoken_mask_commitment_randomness_l, MERCH);
  EcdsaPartialSig_d epsd1 = distribute_EcdsaPartialSig(sig1);
  EcdsaPartialSig_d epsd2 = distribute_EcdsaPartialSig(sig2);

  //PUBLIC values
  Balance_d epsilon_d_merch = distribute_Balance(epsilon_l, MERCH); // IVE BEEN TREATING THIS LIKE A 32 BIT VALUE, BUT ITS 64
  HMACKeyCommitment_d hmac_key_commitment_d_merch = distribute_HMACKeyCommitment(hmac_key_commitment_l, MERCH);
  MaskCommitment_d paytoken_mask_commitment_d_merch = distribute_MaskCommitment(paytoken_mask_commitment_l, MERCH);
  RevLockCommitment_d rlc_d_merch = distribute_RevLockCommitment(rlc_l, MERCH);
  Nonce_d nonce_d_merch = distribute_Nonce(nonce_l, MERCH);
  BitcoinPublicKey_d merch_escrow_pub_key_d_merch = distribute_BitcoinPublicKey(merch_escrow_pub_key_l, MERCH);
  BitcoinPublicKey_d merch_dispute_key_d_merch = distribute_BitcoinPublicKey(merch_dispute_key_l, MERCH);
  BitcoinPublicKey_d merch_payout_pub_key_d_merch = distribute_BitcoinPublicKey(merch_payout_pub_key_l, MERCH);
  PublicKeyHash_d merch_publickey_hash_d_merch = distribute_PublicKeyHash(merch_publickey_hash_l, MERCH);
  //Hardcoded values
  Integer ipad_merch(32, 909522486, MERCH);
  Integer xeight_merch(32, -2147483648, MERCH); //0x80000000;
  Integer threeazero_merch(32, 2048, MERCH); //0x000003a0;
  Integer opad_merch(32, 1549556828, MERCH);
  Integer threehundred_merch(32, 768, MERCH); //0x00000300;
  Integer sixforty_merch(32, 640, MERCH);
  Integer fullF_merch(256, 4294967295 /* 0xffffffff */, MERCH);
  Integer twofivesix_merch(32, 256, MERCH);
  Integer threeeightfour_merch(32, 384, MERCH);
  
  Integer k_merch[64];
  Integer H_merch[8];
  initSHA256(k_merch, H_merch, MERCH);
  
  Integer xsixthreedot_merch = Integer(32, 1671962624 /*0x63a92000*/, MERCH);
  Integer eighteight_merch = Integer(32, 136 /*0x00000088*/, MERCH);
  Integer xtwentyone_merch = Integer(32, 553648128, MERCH);
  Integer sixsevenzero_merch = Integer(32, 26368/*0x00006700*/, MERCH);
  Integer twohundred_merch = Integer(32,2 /*0x000002*/, MERCH);
  Integer xcfzerofive_merch = Integer(32, 3473211392 /*0xcf050000*/, MERCH);
  Integer btwosevenfive_merch = Integer(32, 45685/*0x0000b275*/, MERCH);
  Integer eightninesix_merch = Integer(32, 896, MERCH);
  Integer sixeightac_merch = Integer(32, 26796/*0x000068ac*/, MERCH);
  Integer xtwentytwodot_merch = Integer(32, 570433536 /*0x22002000*/, MERCH);
  Integer sixteen_merch = Integer(32, 22 /*0x00000016*/, MERCH);
  Integer xzerozerofourteen_merch = Integer(32, 1310720 /*0x00140000*/, MERCH);
  Integer threesevensixa_merch = Integer(32, 17258/*0x0000376a*/, MERCH);
  Integer xfourtyone_merch = Integer(32, 1090519040/*0x41000000*/, MERCH);
  Integer eightthousand_merch = Integer(32,32768 /*0x00008000*/, MERCH);
  Integer twelvehundred_merch = Integer(32, 1200, MERCH);
  Integer xzerotwo_merch = Integer(32, 33554432 /*0x02000000*/, MERCH);
  Integer xthreedot_merch = Integer(32, 1001467945  /*0x3bb13029*/, MERCH);
  Integer xcdot_merch = Integer(32, 3464175445 /*0xce7b1f55*/, MERCH);
  Integer xninedot_merch = Integer(32, 2666915655 /*0x9ef5e747*/, MERCH);
  Integer xfdot_merch = Integer(32, 4239147935 /*0xfcac439f*/, MERCH);
  Integer xfourteendot_merch = Integer(32,  341156588 /*0x1455a2ec*/, MERCH);
  Integer xsevendot_merch = Integer(32, 2086603191 /*0x7c5f09b7*/, MERCH);
  Integer xtwentytwoninedot_merch = Integer(32,  579893598 /*0x2290795e*/, MERCH);
  Integer xsevenzerosixdot_merch = Integer(32, 1885753412  /*0x70665044*/, MERCH);
  Integer xfoursevenfivedot_merch = Integer(32, 1196564736/*0x47522100*/, MERCH);
  Integer fivetwoae_merch = Integer(32, 21166/*0x000052ae*/, MERCH);
  Integer fullFthirtytwo_merch = Integer(32, 4294967295 /*0xffffffff*/, MERCH);
  Integer xzeroone_merch = Integer(32, 16777216 /*0x01000000*/, MERCH);
  Integer oneeighttwofour_merch = Integer(32, 1824, MERCH); // 228*8 = 1824 bits
  Integer xseventwosixdot_merch = Integer(32, 1919111713 /* 0x72635221*/, MERCH);
  Integer xzerozerotwentyone_merch = Integer(32, 2162688 /*0x00210000*/, MERCH);
  Integer fiftytwo_merch = Integer(32, 82/*0x00000052*/, MERCH);
  Integer xaedot_merch = Integer(32, 2925986511 /* 0xae6702cf */, MERCH);
  Integer xzerofivedot_merch = Integer(32,   95581473 /* 0x05b27521 */, MERCH);
  Integer acsixeightzerozero_merch = Integer(32, 11298816/* 0x00ac6800 */, MERCH);
  Integer ff_merch = Integer(32, 255 /* 0x000000ff */ , MERCH);
  Integer ffffffzerozero_merch = Integer(32, 4294967040 /*0xffffff00*/, MERCH);
  Integer one_merch = Integer(32, 1 /*0x00000001*/, MERCH);
  Integer eighty_merch = Integer(32, 128 /*0x00000080*/, MERCH);
  Integer twoonesixeight_merch = Integer(32, 2168, MERCH); // 271*8 = 2168 bits

  Integer xzerozeroff_merch = Integer(32, 16711680 /* 00ff0000 */, MERCH);
  Integer ffzerozero_merch = Integer(32, 65280 /* 0000ff00 */, MERCH);
  Integer thirtytwo_merch = Integer(256, 32, MERCH);
  
  Integer q2_merch(516, q2str, MERCH);
  Integer q_merch(258, qstr, MERCH);

  Integer zero_merch(32, 0, MERCH);

  Integer(948, 0, MERCH); //Fix for different number of input wires between parties

  //Compare public inputs + constants to be the same between CUST and MERCH
  Bit error_signal(false);
  for (int i=0; i<2; ++i) {
    error_signal = error_signal | !epsilon_d.balance[i].equal(epsilon_d_merch.balance[i]);
  }
  for (int i=0; i<8; ++i) {
    error_signal = error_signal | !hmac_key_commitment_d.commitment[i].equal(hmac_key_commitment_d_merch.commitment[i]);
  }
  for (int i=0; i<8; ++i) {
    error_signal = error_signal | !paytoken_mask_commitment_d.commitment[i].equal(paytoken_mask_commitment_d_merch.commitment[i]);
  }
  for (int i=0; i<8; ++i) {
    error_signal = error_signal | !rlc_d.commitment[i].equal(rlc_d_merch.commitment[i]);
  }
  for (int i=0; i<4; ++i) {
    error_signal = error_signal | !nonce_d.nonce[i].equal(nonce_d_merch.nonce[i]);
  }
  for (int i=0; i<9; ++i) {
    error_signal = error_signal | !merch_escrow_pub_key_d.key[i].equal(merch_escrow_pub_key_d_merch.key[i]);
  }
  for (int i=0; i<9; ++i) {
    error_signal = error_signal | !merch_dispute_key_d.key[i].equal(merch_dispute_key_d_merch.key[i]);
  }
  for (int i=0; i<9; ++i) {
    error_signal = error_signal | !merch_payout_pub_key_d.key[i].equal(merch_payout_pub_key_d_merch.key[i]);
  }
  for (int i=0; i<5; ++i) {
    error_signal = error_signal | !merch_publickey_hash_d.hash[i].equal(merch_publickey_hash_d_merch.hash[i]);
  }

  error_signal = error_signal | !ipad.equal(ipad_merch);
  error_signal = error_signal | !xeight.equal(xeight_merch);
  error_signal = error_signal | !threeazero.equal(threeazero_merch);
  error_signal = error_signal | !opad.equal(opad_merch);
  error_signal = error_signal | !threehundred.equal(threehundred_merch);
  error_signal = error_signal | !sixforty.equal(sixforty_merch);
  error_signal = error_signal | !fullF.equal(fullF_merch);
  error_signal = error_signal | !twofivesix.equal(twofivesix_merch);
  error_signal = error_signal | !threeeightfour.equal(threeeightfour_merch);

  for (int i=0; i<64; ++i) {
    error_signal = error_signal | !k[i].equal(k_merch[i]);
  }
  for (int i=0; i<8; ++i) {
    error_signal = error_signal | !H[i].equal(H_merch[i]);
  }

  error_signal = error_signal | !xsixthreedot.equal(xsixthreedot_merch);
  error_signal = error_signal | !eighteight.equal(eighteight_merch);
  error_signal = error_signal | !xtwentyone.equal(xtwentyone_merch);
  error_signal = error_signal | !sixsevenzero.equal(sixsevenzero_merch);
  error_signal = error_signal | !twohundred.equal(twohundred_merch);
  error_signal = error_signal | !xcfzerofive.equal(xcfzerofive_merch);
  error_signal = error_signal | !btwosevenfive.equal(btwosevenfive_merch);
  error_signal = error_signal | !eightninesix.equal(eightninesix_merch);
  error_signal = error_signal | !sixeightac.equal(sixeightac_merch);
  error_signal = error_signal | !xtwentytwodot.equal(xtwentytwodot_merch);
  error_signal = error_signal | !sixteen.equal(sixteen_merch);
  error_signal = error_signal | !xzerozerofourteen.equal(xzerozerofourteen_merch);
  error_signal = error_signal | !threesevensixa.equal(threesevensixa_merch);
  error_signal = error_signal | !xfourtyone.equal(xfourtyone_merch);
  error_signal = error_signal | !eightthousand.equal(eightthousand_merch);
  error_signal = error_signal | !twelvehundred.equal(twelvehundred_merch);
  error_signal = error_signal | !xzerotwo.equal(xzerotwo_merch);
  error_signal = error_signal | !xthreedot.equal(xthreedot_merch);
  error_signal = error_signal | !xcdot.equal(xcdot_merch);
  error_signal = error_signal | !xninedot.equal(xninedot_merch);
  error_signal = error_signal | !xfdot.equal(xfdot_merch);
  error_signal = error_signal | !xfourteendot.equal(xfourteendot_merch);
  error_signal = error_signal | !xsevendot.equal(xsevendot_merch);
  error_signal = error_signal | !xtwentytwoninedot.equal(xtwentytwoninedot_merch);
  error_signal = error_signal | !xsevenzerosixdot.equal(xsevenzerosixdot_merch);
  error_signal = error_signal | !xfoursevenfivedot.equal(xfoursevenfivedot_merch);
  error_signal = error_signal | !fivetwoae.equal(fivetwoae_merch);
  error_signal = error_signal | !fullFthirtytwo.equal(fullFthirtytwo_merch);
  error_signal = error_signal | !xzeroone.equal(xzeroone_merch);
  error_signal = error_signal | !oneeighttwofour.equal(oneeighttwofour_merch);
  error_signal = error_signal | !xseventwosixdot.equal(xseventwosixdot_merch);
  error_signal = error_signal | !xzerozerotwentyone.equal(xzerozerotwentyone_merch);
  error_signal = error_signal | !fiftytwo.equal(fiftytwo_merch);
  error_signal = error_signal | !xaedot.equal(xaedot_merch);
  error_signal = error_signal | !xzerofivedot.equal(xzerofivedot_merch);
  error_signal = error_signal | !acsixeightzerozero.equal(acsixeightzerozero_merch);
  error_signal = error_signal | !ff.equal(ff_merch);
  error_signal = error_signal | !ffffffzerozero.equal(ffffffzerozero_merch);
  error_signal = error_signal | !one.equal(one_merch);
  error_signal = error_signal | !eighty.equal(eighty_merch);
  error_signal = error_signal | !twoonesixeight.equal(twoonesixeight_merch);
  
  error_signal = error_signal | !xzerozeroff.equal(xzerozeroff_merch);
  error_signal = error_signal | !ffzerozero.equal(ffzerozero_merch);
  error_signal = error_signal | !thirtytwo.equal(thirtytwo_merch);

  error_signal = error_signal | !q2.equal(q2_merch);
  error_signal = error_signal | !q.equal(q_merch);
  
  error_signal = error_signal | !zero.equal(zero_merch);

#if defined(DEBUG)
  cout << "distributed everything. verifying token sig" << endl;
#endif
// check old pay token
//  verify_token_sig(hmac_key_commitment_d, hmac_commitment_randomness_d, hmac_key_d, old_state_d, old_paytoken_d, ipad, xeight, threeazero, opad, threehundred, sixforty, zero, k, H);
  error_signal = error_signal | verify_token_sig(hmac_key_commitment_d, hmac_commitment_randomness_d, hmac_key_d, old_state_d, old_paytoken_d, ipad, xeight, threeazero, opad, threehundred, sixforty, zero, k, H);

  // make sure old/new state are well-formed
#if defined(DEBUG)
  cout << "comparing old to new state" << endl;
#endif
  error_signal = (error_signal | compare_states(old_state_d, new_state_d, rlc_d, revlock_commitment_randomness_d, nonce_d, epsilon_d, k, H, xeight, zero, threeeightfour));
//  compare_states(old_state_d, new_state_d, rlc_d, revlock_commitment_randomness_d, nonce_d, epsilon_d, k, H, xeight, zero, threeeightfour);

  // constructs new close transactions and computes hash
#if defined(DEBUG)
  cout << "hashing transactions" << endl;
#endif
  Integer escrow_digest[8];
  Integer merch_digest[8];

  validate_transactions(new_state_d,
    cust_escrow_pub_key_d, cust_payout_pub_key_d,
    merch_escrow_pub_key_d, merch_dispute_key_d, merch_payout_pub_key_d,
    merch_publickey_hash_d, escrow_digest, merch_digest, k, H, xeight, twofivesix, zero);

  // we should return into these txserialized_d or hash 

  // sign new close transactions
#if defined(DEBUG)
  cout << "signing transactions" << endl;
#endif

  Integer signed_merch_tx = ecdsa_sign_hashed(merch_digest, epsd1, thirtytwo, q, q2);
  Integer signed_escrow_tx = ecdsa_sign_hashed(escrow_digest, epsd2, thirtytwo, q, q2);

  // sign new pay token
#if defined(DEBUG)
  cout << "signing token" << endl;
#endif
  PayToken_d new_paytoken_d = sign_token(new_state_d, hmac_key_d, ipad, xeight, threeazero, opad, threehundred, zero, k, H);

  // Transform the signed_merch_tx into the correct format --> array of 8 32bit uints
  EcdsaSig_d signed_merch_tx_parsed;
  EcdsaSig_d signed_escrow_tx_parsed;

  bigint_into_smallint_array(signed_merch_tx_parsed.sig, signed_merch_tx, fullF);
  bigint_into_smallint_array(signed_escrow_tx_parsed.sig, signed_escrow_tx, fullF);

  // mask pay and close tokens
#if defined(DEBUG)
  cout << "masking pay token" << endl;
#endif
  error_signal = ( error_signal | mask_paytoken(new_paytoken_d.paytoken, paytoken_mask_d, paytoken_mask_commitment_d, paytoken_mask_commitment_randomness_d, k, H, xeight, zero, threeeightfour)); // pay token
//  mask_paytoken(new_paytoken_d.paytoken, paytoken_mask_d, paytoken_mask_commitment_d, paytoken_mask_commitment_randomness_d, k, H, xeight, zero, threeeightfour); // pay token

#if defined(DEBUG)
  cout << "masking close merch token" << endl;
#endif
  mask_closetoken(signed_merch_tx_parsed.sig, merch_mask_d); // close token - merchant close

#if defined(DEBUG)
  cout << "masking close escrow token" << endl;
#endif
  mask_closetoken(signed_escrow_tx_parsed.sig, escrow_mask_d); // close token - escrow close

  // handle errors
  // If there has been an error, we need to destroy the token values.
#if defined(DEBUG)
  cout << "handling errors" << endl;
#endif
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
#if defined(DEBUG)
  cout << "customer finished!" << endl;
#endif
  if (io1 != nullptr) delete io1;
  if (io2 != nullptr) delete io2;
  if (io3 != nullptr) delete io3;
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

#if defined(DEBUG)
  cout << "merchant finished!" << endl;
#endif
  if (io1 != nullptr) delete io1;
  if (io2 != nullptr) delete io2;
  if (io3 != nullptr) delete io3;
}

PayToken_d sign_token(State_d state, HMACKey_d key, Integer ipad, Integer xeight, Integer threeazero, Integer opad, Integer threehundred, Integer zero, Integer k[64], Integer H[8]) {
  PayToken_d paytoken;
  HMACsign(key, state, paytoken.paytoken, ipad, xeight, threeazero, opad, threehundred, zero, k, H);
  return paytoken;
}

Bit verify_token_sig(HMACKeyCommitment_d commitment, CommitmentRandomness_d hmac_commitment_randomness_d, HMACKey_d opening, State_d old_state, PayToken_d old_paytoken, Integer ipad, Integer xeight, Integer threeazero, Integer opad, Integer threehundred, Integer sixforty, Integer zero, Integer k[64], Integer H[8]) {

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
//  message[1][4] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[1][4] = xeight; //0x80000000;
  message[1][5] = zero; //0x00000000;
  message[1][6] = zero; //0x00000000;
  message[1][7] = zero; //0x00000000;
  message[1][8] = zero; //0x00000000;
  message[1][9] = zero; //0x00000000;
  message[1][10] = zero; //0x00000000;
  message[1][11] = zero; //0x00000000;
  message[1][12] = zero; //0x00000000;
  message[1][13] = zero; //0x00000000;

  // Message length 
  message[1][14] = zero; //0x00000000;
//  message[1][15] = Integer(32, 640, PUBLIC);
  message[1][15] = sixforty;

  Integer hashresult[8];

  computeSHA256_2d_noinit(message, hashresult, k, H);

  Bit b; // TODO initialize to 0

  for(int i=0; i<8; i++) {
     Bit not_equal = !(commitment.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }

  // // Sign the old state again to compare
  PayToken_d recomputed_paytoken;
  HMACsign(opening, old_state, recomputed_paytoken.paytoken, ipad, xeight, threeazero, opad, threehundred, zero, k, H);

  for(int i=0; i<8; i++) {
    Bit not_equal = !(recomputed_paytoken.paytoken[i].equal(old_paytoken.paytoken[i]));
    b = b | not_equal;
  }
  return b;
}

// make sure wallets are well-formed
Bit compare_states(State_d old_state_d, State_d new_state_d, RevLockCommitment_d rlc_d, CommitmentRandomness_d revlock_commitment_randomness_d, Nonce_d nonce_d, Balance_d epsilon_d, Integer k[64], Integer H[8], Integer xeight, Integer zero, Integer threeeightfour) {

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
  b = (b | verify_revlock_commitment(old_state_d.rl, rlc_d, revlock_commitment_randomness_d, k, H, xeight, zero, threeeightfour));

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
  Integer zero64 = zero.resize(64, false);

  b = (b | (!(old_balance_merch_combined + epsilon_combined).geq(zero64)));
  b = (b | (!(old_balance_cust_combined - epsilon_combined).geq(zero64)));

  return b;
}

// make sure customer committed to this new wallet
Bit open_commitment() {
  Bit b;
  return b;
}

Bit verify_revlock_commitment(RevLock_d rl_d, RevLockCommitment_d rlc_d, CommitmentRandomness_d rl_rand_d, Integer k[64], Integer H[8], Integer xeight, Integer zero, Integer threeeightfour) {
  Bit b;  // TODO initialize to 0

  Integer message[1][16];

  for(int i=0; i<8; i++) {
    message[0][i] = rl_d.revlock[i];
  }

  message[0][8] = rl_rand_d.randomness[0];
  message[0][9] = rl_rand_d.randomness[1];
  message[0][10] = rl_rand_d.randomness[2];
  message[0][11] = rl_rand_d.randomness[3];
//  message[0][12] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[0][12] = xeight; //0x80000000;
  message[0][13] = zero; //0x00000000;

  // Message length 
  message[0][14] = zero; //0x00000000;
  message[0][15] = threeeightfour; // 256 bit RL
//  message[0][15] = Integer(32, 384, PUBLIC); // 256 bit RL

  Integer hashresult[8];

  computeSHA256_1d_noinit(message, hashresult, k, H);

  for(int i=0; i<8; i++) {
     Bit not_equal = !(rlc_d.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }
  return b;
}

Bit verify_mask_commitment(Mask_d mask, MaskCommitment_d maskcommitment, CommitmentRandomness_d mask_commitment_randomness_d, Integer k[64], Integer H[8], Integer xeight, Integer zero, Integer threeeightfour) {
  Bit b;  // TODO initialize to 0

  Integer message[1][16];

  for(int i=0; i<8; i++) {
    message[0][i] = mask.mask[i];
  }

  message[0][8] = mask_commitment_randomness_d.randomness[0];
  message[0][9] = mask_commitment_randomness_d.randomness[1];
  message[0][10] = mask_commitment_randomness_d.randomness[2];
  message[0][11] = mask_commitment_randomness_d.randomness[3];
//  message[0][12] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[0][12] = xeight; //0x80000000;
  message[0][13] = zero; //0x00000000;

  // Message length 
  message[0][14] = zero; //0x00000000;
  message[0][15] = threeeightfour;

  Integer hashresult[8];

  computeSHA256_1d_noinit(message, hashresult, k, H);

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
  PublicKeyHash_d merch_publickey_hash_d, Integer escrow_digest[8], Integer merch_digest[8], Integer k[64], Integer H[8], Integer xeight, Integer twofivesix, Integer zero)
{
  // 112 bytes --> 896
  Integer customer_delayed_script_hash_preimage[2][16];

  // OPCODE || 1 byte of Rev Lock  0x63a82000  1671962624
  customer_delayed_script_hash_preimage[0][0] = xsixthreedot | /* First byte of revlock*/(new_state_d.rl.revlock[0] >> 24);
//  customer_delayed_script_hash_preimage[0][0] = Integer(32, 1671962624 /*0x63a92000*/, PUBLIC) | /* First byte of revlock*/(new_state_d.rl.revlock[0] >> 24);

  // 31 remaining bytes of Rev Lock
  customer_delayed_script_hash_preimage[0][1] = (/* last 3 bytes */ new_state_d.rl.revlock[0] << 8) | ( /* first byte of the next int */ new_state_d.rl.revlock[1] >> 24);
  customer_delayed_script_hash_preimage[0][2] = (new_state_d.rl.revlock[1] << 8) | (new_state_d.rl.revlock[2] >> 24);
  customer_delayed_script_hash_preimage[0][3] = (new_state_d.rl.revlock[2] << 8) | (new_state_d.rl.revlock[3] >> 24);
  customer_delayed_script_hash_preimage[0][4] = (new_state_d.rl.revlock[3] << 8) | (new_state_d.rl.revlock[4] >> 24);
  customer_delayed_script_hash_preimage[0][5] = (new_state_d.rl.revlock[4] << 8) | (new_state_d.rl.revlock[5] >> 24);
  customer_delayed_script_hash_preimage[0][6] = (new_state_d.rl.revlock[5] << 8) | (new_state_d.rl.revlock[6] >> 24);
  customer_delayed_script_hash_preimage[0][7] = (new_state_d.rl.revlock[6] << 8) | (new_state_d.rl.revlock[7] >> 24);
  customer_delayed_script_hash_preimage[0][8] = (new_state_d.rl.revlock[7] << 8) | eighteight;
//  customer_delayed_script_hash_preimage[0][8] = (new_state_d.rl.revlock[7] << 8) | Integer(32, 136 /*0x00000088*/, PUBLIC);

  customer_delayed_script_hash_preimage[0][9]  = xtwentyone | merch_dispute_key_d.key[0] >> 8; //0x21000000 // taking 3 bytes from the key
//  customer_delayed_script_hash_preimage[0][9]  = Integer(32, 553648128, PUBLIC) | merch_dispute_key_d.key[0] >> 8; //0x21000000 // taking 3 bytes from the key
  customer_delayed_script_hash_preimage[0][10] = (merch_dispute_key_d.key[0] << 24) | (merch_dispute_key_d.key[1] >> 8); // byte 4-7
  customer_delayed_script_hash_preimage[0][11] = (merch_dispute_key_d.key[1] << 24) | (merch_dispute_key_d.key[2] >> 8); // byte 8-11
  customer_delayed_script_hash_preimage[0][12] = (merch_dispute_key_d.key[2] << 24) | (merch_dispute_key_d.key[3] >> 8); // bytes 12-15
  customer_delayed_script_hash_preimage[0][13] = (merch_dispute_key_d.key[3] << 24) | (merch_dispute_key_d.key[4] >> 8); // bytes 16-19
  customer_delayed_script_hash_preimage[0][14] = (merch_dispute_key_d.key[4] << 24) | (merch_dispute_key_d.key[5] >> 8); // bytes 20-23
  customer_delayed_script_hash_preimage[0][15] = (merch_dispute_key_d.key[5] << 24) | (merch_dispute_key_d.key[6] >> 8); // bytes 24-27
  customer_delayed_script_hash_preimage[1][0]  = (merch_dispute_key_d.key[6] << 24) | (merch_dispute_key_d.key[7] >> 8); // bytes 28-31
  customer_delayed_script_hash_preimage[1][1]  = (merch_dispute_key_d.key[7] << 24) | (merch_dispute_key_d.key[8] >> 8) | sixsevenzero | twohundred; // bytes 32-33 // 0x67
//  customer_delayed_script_hash_preimage[1][1]  = (merch_dispute_key_d.key[7] << 24) | (merch_dispute_key_d.key[8] >> 8) | Integer(32, 26368/*0x00006700*/, PUBLIC) | Integer(32,2 /*0x000002*/, PUBLIC); // bytes 32-33 // 0x67

  // This previous last byte and the following to bytes is the delay.  We should talk about how long we want them to be
  customer_delayed_script_hash_preimage[1][2]  = xcfzerofive | btwosevenfive;
//  customer_delayed_script_hash_preimage[1][2]  = Integer(32, 3473211392 /*0xcf050000*/, PUBLIC) | Integer(32, 45685/*0x0000b275*/, PUBLIC);
  customer_delayed_script_hash_preimage[1][3]  = xtwentyone  | (cust_payout_pub_key_d.key[0] >> 8);
//  customer_delayed_script_hash_preimage[1][3]  = Integer(32, 553648128 /*0x21000000*/, PUBLIC)  | (cust_payout_pub_key_d.key[0] >> 8);
  customer_delayed_script_hash_preimage[1][4]  = (cust_payout_pub_key_d.key[0] << 24) | (cust_payout_pub_key_d.key[1] >> 8);
  customer_delayed_script_hash_preimage[1][5]  = (cust_payout_pub_key_d.key[1] << 24) | (cust_payout_pub_key_d.key[2] >> 8);
  customer_delayed_script_hash_preimage[1][6]  = (cust_payout_pub_key_d.key[2] << 24) | (cust_payout_pub_key_d.key[3] >> 8);
  customer_delayed_script_hash_preimage[1][7]  = (cust_payout_pub_key_d.key[3] << 24) | (cust_payout_pub_key_d.key[4] >> 8);
  customer_delayed_script_hash_preimage[1][8]  = (cust_payout_pub_key_d.key[4] << 24) | (cust_payout_pub_key_d.key[5] >> 8);
  customer_delayed_script_hash_preimage[1][9]  = (cust_payout_pub_key_d.key[5] << 24) | (cust_payout_pub_key_d.key[6] >> 8);
  customer_delayed_script_hash_preimage[1][10] = (cust_payout_pub_key_d.key[6] << 24) | (cust_payout_pub_key_d.key[7] >> 8);
  customer_delayed_script_hash_preimage[1][11] = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | sixeightac;
//  customer_delayed_script_hash_preimage[1][11] = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | Integer(32, 26796/*0x000068ac*/, PUBLIC);

  customer_delayed_script_hash_preimage[1][12] = xeight;
//  customer_delayed_script_hash_preimage[1][12] = Integer(32, -2147483648/*0x80000000*/, PUBLIC);
  customer_delayed_script_hash_preimage[1][13] = zero; //0x00000000;
  customer_delayed_script_hash_preimage[1][14] = zero; //0x00000000;
  customer_delayed_script_hash_preimage[1][15] = eightninesix;
//  customer_delayed_script_hash_preimage[1][15] = Integer(32, 896, PUBLIC);

  Integer customer_delayed_script_hash[8];

  // dump_buffer("cust_deplay_script_preimage0=", customer_delayed_script_hash_preimage[0]);
  // dump_buffer("cust_deplay_script_preimage1=", customer_delayed_script_hash_preimage[1]);

  computeSHA256_2d_noinit(customer_delayed_script_hash_preimage, customer_delayed_script_hash, k, H);

  // 150 bytes
  Integer hash_outputs_preimage[3][16];

  Balance_d little_endian_balance_cust = convert_to_little_endian(new_state_d.balance_cust, xzerozeroff, ffzerozero);
  Balance_d little_endian_balance_merch = convert_to_little_endian(new_state_d.balance_merch, xzerozeroff, ffzerozero);

  hash_outputs_preimage[0][0]  = little_endian_balance_cust.balance[0];// first bytes of customer balance // FIX ENDIANNESS
  hash_outputs_preimage[0][1]  = little_endian_balance_cust.balance[1];// second bytes of customer blanace // FIX ENDIANNESS

  hash_outputs_preimage[0][2]  = xtwentytwodot | (customer_delayed_script_hash[0] >> 24); // OPCODE and the first byte of the prev hash output
//  hash_outputs_preimage[0][2]  = Integer(32, 570433536 /*0x22002000*/, PUBLIC) | (customer_delayed_script_hash[0] >> 24); // OPCODE and the first byte of the prev hash output
  hash_outputs_preimage[0][3]  = (customer_delayed_script_hash[0] << 8) | (customer_delayed_script_hash[1] >> 24); // end of byte 1 and first byte of 2...
  hash_outputs_preimage[0][4]  = (customer_delayed_script_hash[1] << 8) | (customer_delayed_script_hash[2] >> 24);
  hash_outputs_preimage[0][5]  = (customer_delayed_script_hash[2] << 8) | (customer_delayed_script_hash[3] >> 24);
  hash_outputs_preimage[0][6]  = (customer_delayed_script_hash[3] << 8) | (customer_delayed_script_hash[4] >> 24);
  hash_outputs_preimage[0][7]  = (customer_delayed_script_hash[4] << 8) | (customer_delayed_script_hash[5] >> 24);
  hash_outputs_preimage[0][8]  = (customer_delayed_script_hash[5] << 8) | (customer_delayed_script_hash[6] >> 24);
  hash_outputs_preimage[0][9]  = (customer_delayed_script_hash[6] << 8) | (customer_delayed_script_hash[7] >> 24);
  hash_outputs_preimage[0][10] = (customer_delayed_script_hash[7] << 8) |  (little_endian_balance_merch.balance[0] >> 24);/*first byte of merch balance >> 24*/;
  hash_outputs_preimage[0][11] =  (little_endian_balance_merch.balance[0] << 8) | (little_endian_balance_merch.balance[1] >> 24);
  hash_outputs_preimage[0][12] =  (little_endian_balance_merch.balance[1] << 8) | sixteen;
//  hash_outputs_preimage[0][12] =  (little_endian_balance_merch.balance[1] << 8) | Integer(32, 22 /*0x00000016*/, PUBLIC);
  hash_outputs_preimage[0][13] = xzerozerofourteen | (merch_publickey_hash_d.hash[0] >> 16);
//  hash_outputs_preimage[0][13] = Integer(32, 1310720 /*0x00140000*/, PUBLIC) | (merch_publickey_hash_d.hash[0] >> 16);
  hash_outputs_preimage[0][14] = (merch_publickey_hash_d.hash[0] << 16) | (merch_publickey_hash_d.hash[1] >> 16);
  hash_outputs_preimage[0][15] = (merch_publickey_hash_d.hash[1] << 16) | (merch_publickey_hash_d.hash[2] >> 16);
  hash_outputs_preimage[1][0]  = (merch_publickey_hash_d.hash[2] << 16) | (merch_publickey_hash_d.hash[3] >> 16);
  hash_outputs_preimage[1][1]  = (merch_publickey_hash_d.hash[3] << 16) | (merch_publickey_hash_d.hash[4] >> 16);
  hash_outputs_preimage[1][2]  = (merch_publickey_hash_d.hash[4] << 16) | zero; //Two bytes of the OP_Return Amount
  hash_outputs_preimage[1][3]  = zero; // middle 4 bytes of OP_RETURN amount
  hash_outputs_preimage[1][4]  = threesevensixa; // OPRETURN FORMATTING
//  hash_outputs_preimage[1][4]  = Integer(32, 17258/*0x0000376a*/,PUBLIC); // OPRETURN FORMATTING
  hash_outputs_preimage[1][5] = xfourtyone /*last byte of opreturn formatting */ | (new_state_d.rl.revlock[0] >> 8);
//  hash_outputs_preimage[1][5] = Integer(32, 1090519040/*0x41000000*/,PUBLIC)/*last byte of opreturn formatting */ | (new_state_d.rl.revlock[0] >> 8);

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
  hash_outputs_preimage[2][5]  = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | eightthousand; //33
//  hash_outputs_preimage[2][5]  = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | Integer(32,32768 /*0x00008000*/, PUBLIC); //33

  hash_outputs_preimage[2][6]  = zero;
  hash_outputs_preimage[2][7]  = zero;
  hash_outputs_preimage[2][8]  = zero;
  hash_outputs_preimage[2][9]  = zero;
  hash_outputs_preimage[2][10] = zero;
  hash_outputs_preimage[2][11] = zero;
  hash_outputs_preimage[2][12] = zero;
  hash_outputs_preimage[2][13] = zero;
  hash_outputs_preimage[2][14] = zero; //0x00000000;
  hash_outputs_preimage[2][15] = twelvehundred;
//  hash_outputs_preimage[2][15] = Integer(32, 1200, PUBLIC);

  Integer hash_outputs[8];


  computeDoubleSHA256_3d_noinit(hash_outputs_preimage, hash_outputs, k, H, xeight, twofivesix, zero);


  // The total preimage is 228 bytes
  Integer total_preimage_escrow[4][16];

  total_preimage_escrow[0][0] = xzerotwo;
//  total_preimage_escrow[0][0] = Integer(32, 33554432 /*0x02000000*/, PUBLIC);
  total_preimage_escrow[0][1] = new_state_d.HashPrevOuts_escrow.txid[0];
  total_preimage_escrow[0][2] = new_state_d.HashPrevOuts_escrow.txid[1];
  total_preimage_escrow[0][3] = new_state_d.HashPrevOuts_escrow.txid[2];
  total_preimage_escrow[0][4] = new_state_d.HashPrevOuts_escrow.txid[3];
  total_preimage_escrow[0][5] = new_state_d.HashPrevOuts_escrow.txid[4];
  total_preimage_escrow[0][6] = new_state_d.HashPrevOuts_escrow.txid[5];
  total_preimage_escrow[0][7] = new_state_d.HashPrevOuts_escrow.txid[6];
  total_preimage_escrow[0][8] = new_state_d.HashPrevOuts_escrow.txid[7];

  total_preimage_escrow[0][9]  =  xthreedot;
  total_preimage_escrow[0][10] =  xcdot;
  total_preimage_escrow[0][11] =  xninedot;
  total_preimage_escrow[0][12] =  xfdot;
  total_preimage_escrow[0][13] =  xfourteendot;
  total_preimage_escrow[0][14] =  xsevendot;
  total_preimage_escrow[0][15] =  xtwentytwoninedot;
  total_preimage_escrow[1][0]  =  xsevenzerosixdot;
// total_preimage_escrow[0][9]  =  Integer(32, 1001467945  /*0x3bb13029*/, PUBLIC);
//  total_preimage_escrow[0][10] =  Integer(32, 3464175445 /*0xce7b1f55*/, PUBLIC);
//  total_preimage_escrow[0][11] =  Integer(32, 2666915655 /*0x9ef5e747*/, PUBLIC);
//  total_preimage_escrow[0][12] =  Integer(32, 4239147935 /*0xfcac439f*/, PUBLIC);
//  total_preimage_escrow[0][13] =  Integer(32,  341156588 /*0x1455a2ec*/, PUBLIC);
//  total_preimage_escrow[0][14] =  Integer(32, 2086603191 /*0x7c5f09b7*/, PUBLIC);
//  total_preimage_escrow[0][15] =  Integer(32,  579893598 /*0x2290795e*/, PUBLIC);
//  total_preimage_escrow[1][0]  =  Integer(32, 1885753412  /*0x70665044*/, PUBLIC);

  total_preimage_escrow[1][1] = new_state_d.txid_escrow.txid[0];
  total_preimage_escrow[1][2] = new_state_d.txid_escrow.txid[1];
  total_preimage_escrow[1][3] = new_state_d.txid_escrow.txid[2];
  total_preimage_escrow[1][4] = new_state_d.txid_escrow.txid[3];
  total_preimage_escrow[1][5] = new_state_d.txid_escrow.txid[4];
  total_preimage_escrow[1][6] = new_state_d.txid_escrow.txid[5];
  total_preimage_escrow[1][7] = new_state_d.txid_escrow.txid[6];
  total_preimage_escrow[1][8] = new_state_d.txid_escrow.txid[7];

  total_preimage_escrow[1][9] = zero;

  total_preimage_escrow[1][10]  = xfoursevenfivedot | (merch_escrow_pub_key_d.key[0] >> 24);
//  total_preimage_escrow[1][10]  = Integer(32, 1196564736/*0x47522100*/, PUBLIC) | (merch_escrow_pub_key_d.key[0] >> 24);
  total_preimage_escrow[1][11] = (merch_escrow_pub_key_d.key[0] << 8) | (merch_escrow_pub_key_d.key[1] >> 24);
  total_preimage_escrow[1][12] = (merch_escrow_pub_key_d.key[1] << 8) | (merch_escrow_pub_key_d.key[2] >> 24);
  total_preimage_escrow[1][13] = (merch_escrow_pub_key_d.key[2] << 8) | (merch_escrow_pub_key_d.key[3] >> 24);
  total_preimage_escrow[1][14] = (merch_escrow_pub_key_d.key[3] << 8) | (merch_escrow_pub_key_d.key[4] >> 24);
  total_preimage_escrow[1][15] = (merch_escrow_pub_key_d.key[4] << 8) | (merch_escrow_pub_key_d.key[5] >> 24);
  total_preimage_escrow[2][0] = (merch_escrow_pub_key_d.key[5] << 8) | (merch_escrow_pub_key_d.key[6] >> 24);
  total_preimage_escrow[2][1]  = (merch_escrow_pub_key_d.key[6] << 8) | (merch_escrow_pub_key_d.key[7] >> 24);
  total_preimage_escrow[2][2]  = (merch_escrow_pub_key_d.key[7] << 8) | (merch_escrow_pub_key_d.key[8] >> 24);
  total_preimage_escrow[2][3]  = xtwentyone | (cust_escrow_pub_key_d.key[0] >> 8);  // first three bytes of the cust public key
//  total_preimage_escrow[2][3]  = Integer(32, 553648128 /*0x21000000*/, PUBLIC) | (cust_escrow_pub_key_d.key[0] >> 8);  // first three bytes of the cust public key
  // 30 more bytes of key
  total_preimage_escrow[2][4]  = (cust_escrow_pub_key_d.key[0] << 24)| (cust_escrow_pub_key_d.key[1] >> 8);
  total_preimage_escrow[2][5]  = (cust_escrow_pub_key_d.key[1] << 24)| (cust_escrow_pub_key_d.key[2] >> 8);
  total_preimage_escrow[2][6]  = (cust_escrow_pub_key_d.key[2] << 24)| (cust_escrow_pub_key_d.key[3] >> 8);
  total_preimage_escrow[2][7]  = (cust_escrow_pub_key_d.key[3] << 24)| (cust_escrow_pub_key_d.key[4] >> 8);
  total_preimage_escrow[2][8]  = (cust_escrow_pub_key_d.key[4] << 24)| (cust_escrow_pub_key_d.key[5] >> 8);
  total_preimage_escrow[2][9]  = (cust_escrow_pub_key_d.key[5] << 24)| (cust_escrow_pub_key_d.key[6] >> 8);
  total_preimage_escrow[2][10]  = (cust_escrow_pub_key_d.key[6] << 24)| (cust_escrow_pub_key_d.key[7] >> 8);
  total_preimage_escrow[2][11] = (cust_escrow_pub_key_d.key[7] << 24)| (cust_escrow_pub_key_d.key[8] >> 8) | fivetwoae;
//  total_preimage_escrow[2][11] = (cust_escrow_pub_key_d.key[7] << 24)| (cust_escrow_pub_key_d.key[8] >> 8) | Integer(32, 21166/*0x000052ae*/, PUBLIC);

  Balance_d big_endian_total_amount = sum_balances(new_state_d.balance_cust, new_state_d.balance_merch, zero);
  Balance_d little_endian_total_amount = convert_to_little_endian(big_endian_total_amount, xzerozeroff, ffzerozero);
  total_preimage_escrow[2][12] = little_endian_total_amount.balance[0];
  total_preimage_escrow[2][13] = little_endian_total_amount.balance[1];

  total_preimage_escrow[2][14] = fullFthirtytwo;
//  total_preimage_escrow[2][14] = Integer(32, 4294967295 /*0xffffffff*/, PUBLIC);

  total_preimage_escrow[2][15] = hash_outputs[0];
  total_preimage_escrow[3][0]  = hash_outputs[1];
  total_preimage_escrow[3][1]  = hash_outputs[2];
  total_preimage_escrow[3][2]  = hash_outputs[3];
  total_preimage_escrow[3][3]  = hash_outputs[4];
  total_preimage_escrow[3][4]  = hash_outputs[5];
  total_preimage_escrow[3][5]  = hash_outputs[6];
  total_preimage_escrow[3][6]  = hash_outputs[7];

  total_preimage_escrow[3][7]  = zero;
  total_preimage_escrow[3][8]  = xzeroone;
//  total_preimage_escrow[3][8]  = Integer(32, 16777216 /*0x01000000*/, PUBLIC);

  total_preimage_escrow[3][9]   = xeight;
//  total_preimage_escrow[3][9]   = Integer(32, -2147483648/*0x80000000*/, PUBLIC);
  total_preimage_escrow[3][10]  = zero;
  total_preimage_escrow[3][11]  = zero;
  total_preimage_escrow[3][12]  = zero;
  total_preimage_escrow[3][13]  = zero;
  total_preimage_escrow[3][14]  = zero; //0x00000000;
  total_preimage_escrow[3][15]  = oneeighttwofour; // 228*8 = 1824 bits
//  total_preimage_escrow[3][15]  = Integer(32, 1824, PUBLIC); // 228*8 = 1824 bits


  // Integer escrow_digest[8];
  computeDoubleSHA256_4d_noinit(total_preimage_escrow, escrow_digest, k, H, xeight, twofivesix, zero);

    // The total preimage is 228 bytes
  Integer total_preimage_merch[5][16];

  total_preimage_merch[0][0] = xzerotwo;
//  total_preimage_merch[0][0] = Integer(32, 33554432 /*0x02000000*/, PUBLIC);
  total_preimage_merch[0][1] = new_state_d.HashPrevOuts_merch.txid[0];
  total_preimage_merch[0][2] = new_state_d.HashPrevOuts_merch.txid[1];
  total_preimage_merch[0][3] = new_state_d.HashPrevOuts_merch.txid[2];
  total_preimage_merch[0][4] = new_state_d.HashPrevOuts_merch.txid[3];
  total_preimage_merch[0][5] = new_state_d.HashPrevOuts_merch.txid[4];
  total_preimage_merch[0][6] = new_state_d.HashPrevOuts_merch.txid[5];
  total_preimage_merch[0][7] = new_state_d.HashPrevOuts_merch.txid[6];
  total_preimage_merch[0][8] = new_state_d.HashPrevOuts_merch.txid[7];

  total_preimage_merch[0][9]  =  xthreedot;
  total_preimage_merch[0][10] =  xcdot;
  total_preimage_merch[0][11] =  xninedot;
  total_preimage_merch[0][12] =  xfdot;
  total_preimage_merch[0][13] =  xfourteendot;
  total_preimage_merch[0][14] =  xsevendot;
  total_preimage_merch[0][15] =  xtwentytwoninedot;
  total_preimage_merch[1][0]  =  xsevenzerosixdot;
  // total_preimage_escrow[0][9]  =  Integer(32, 1001467945  /*0x3bb13029*/, PUBLIC);
  //  total_preimage_escrow[0][10] =  Integer(32, 3464175445 /*0xce7b1f55*/, PUBLIC);
  //  total_preimage_escrow[0][11] =  Integer(32, 2666915655 /*0x9ef5e747*/, PUBLIC);
  //  total_preimage_escrow[0][12] =  Integer(32, 4239147935 /*0xfcac439f*/, PUBLIC);
  //  total_preimage_escrow[0][13] =  Integer(32,  341156588 /*0x1455a2ec*/, PUBLIC);
  //  total_preimage_escrow[0][14] =  Integer(32, 2086603191 /*0x7c5f09b7*/, PUBLIC);
  //  total_preimage_escrow[0][15] =  Integer(32,  579893598 /*0x2290795e*/, PUBLIC);
  //  total_preimage_escrow[1][0]  =  Integer(32, 1885753412  /*0x70665044*/, PUBLIC);

  total_preimage_merch[1][1] = new_state_d.txid_merch.txid[0];
  total_preimage_merch[1][2] = new_state_d.txid_merch.txid[1];
  total_preimage_merch[1][3] = new_state_d.txid_merch.txid[2];
  total_preimage_merch[1][4] = new_state_d.txid_merch.txid[3];
  total_preimage_merch[1][5] = new_state_d.txid_merch.txid[4];
  total_preimage_merch[1][6] = new_state_d.txid_merch.txid[5];
  total_preimage_merch[1][7] = new_state_d.txid_merch.txid[6];
  total_preimage_merch[1][8] = new_state_d.txid_merch.txid[7];

  total_preimage_merch[1][9] = zero;

  // The script
  total_preimage_merch[1][10] = xseventwosixdot;
//  total_preimage_merch[1][10] = Integer(32, 1919111713 /* 0x72635221*/, PUBLIC);

  total_preimage_merch[1][11] = merch_escrow_pub_key_d.key[0];
  total_preimage_merch[1][12] = merch_escrow_pub_key_d.key[1];
  total_preimage_merch[1][13] = merch_escrow_pub_key_d.key[2];
  total_preimage_merch[1][14] = merch_escrow_pub_key_d.key[3];
  total_preimage_merch[1][15] = merch_escrow_pub_key_d.key[4];
  total_preimage_merch[2][0]  = merch_escrow_pub_key_d.key[5];
  total_preimage_merch[2][1]  = merch_escrow_pub_key_d.key[6];
  total_preimage_merch[2][2]  = merch_escrow_pub_key_d.key[7];
  total_preimage_merch[2][3]  = merch_escrow_pub_key_d.key[8] | xzerozerotwentyone | (cust_escrow_pub_key_d.key[0] >> 16);
//  total_preimage_merch[2][3]  = merch_escrow_pub_key_d.key[8] | Integer(32, 2162688 /*0x00210000*/, PUBLIC) | (cust_escrow_pub_key_d.key[0] >> 16);

  // 31 more bytes of key
  total_preimage_merch[2][4]  = (cust_escrow_pub_key_d.key[0] << 16)| (cust_escrow_pub_key_d.key[1] >> 16);
  total_preimage_merch[2][5]  = (cust_escrow_pub_key_d.key[1] << 16)| (cust_escrow_pub_key_d.key[2] >> 16);
  total_preimage_merch[2][6]  = (cust_escrow_pub_key_d.key[2] << 16)| (cust_escrow_pub_key_d.key[3] >> 16);
  total_preimage_merch[2][7]  = (cust_escrow_pub_key_d.key[3] << 16)| (cust_escrow_pub_key_d.key[4] >> 16);
  total_preimage_merch[2][8]  = (cust_escrow_pub_key_d.key[4] << 16)| (cust_escrow_pub_key_d.key[5] >> 16);
  total_preimage_merch[2][9]  = (cust_escrow_pub_key_d.key[5] << 16)| (cust_escrow_pub_key_d.key[6] >> 16);
  total_preimage_merch[2][10] = (cust_escrow_pub_key_d.key[6] << 16)| (cust_escrow_pub_key_d.key[7] >> 16);
  total_preimage_merch[2][11] = (cust_escrow_pub_key_d.key[7] << 16)| (cust_escrow_pub_key_d.key[8] >> 16) | fiftytwo;
//  total_preimage_merch[2][11] = (cust_escrow_pub_key_d.key[7] << 16)| (cust_escrow_pub_key_d.key[8] >> 16) | Integer(32, 82/*0x00000052*/, PUBLIC);

  total_preimage_merch[2][12] = xaedot;
//  total_preimage_merch[2][12] = Integer(32, 2925986511 /* 0xae6702cf */, PUBLIC);
  total_preimage_merch[2][13] = xzerofivedot;
//  total_preimage_merch[2][13] = Integer(32,   95581473 /* 0x05b27521 */, PUBLIC);

  /* merch-payout-key*/
  total_preimage_merch[2][14] = merch_payout_pub_key_d.key[0];
  total_preimage_merch[2][15] = merch_payout_pub_key_d.key[1];
  total_preimage_merch[3][0]  = merch_payout_pub_key_d.key[2];
  total_preimage_merch[3][1]  = merch_payout_pub_key_d.key[3];
  total_preimage_merch[3][2]  = merch_payout_pub_key_d.key[4];
  total_preimage_merch[3][3]  = merch_payout_pub_key_d.key[5];
  total_preimage_merch[3][4]  = merch_payout_pub_key_d.key[6];
  total_preimage_merch[3][5]  = merch_payout_pub_key_d.key[7]; // FIRST 3 bytes of the amount
  total_preimage_merch[3][6]  = merch_payout_pub_key_d.key[8] | acsixeightzerozero | (little_endian_total_amount.balance[0]>>24);
//  total_preimage_merch[3][6]  = merch_payout_pub_key_d.key[8] | Integer(32, 11298816/* 0x00ac6800 */, PUBLIC) | (little_endian_total_amount.balance[0]>>24);

  total_preimage_merch[3][7] = (little_endian_total_amount.balance[0] << 8) | (little_endian_total_amount.balance[1] >> 24);

  total_preimage_merch[3][8] = (little_endian_total_amount.balance[1] << 8) | ff;
//  total_preimage_merch[3][8] = (little_endian_total_amount.balance[1] << 8) | Integer (32, 255 /* 0x000000ff */ , PUBLIC);
  total_preimage_merch[3][9] = ffffffzerozero | (hash_outputs[0] >> 24);
//  total_preimage_merch[3][9] = Integer(32, 4294967040 /*0xffffff00*/, PUBLIC) | (hash_outputs[0] >> 24);

  total_preimage_merch[3][10] =  (hash_outputs[0] << 8) | (hash_outputs[1] >> 24);
  total_preimage_merch[3][11] =  (hash_outputs[1] << 8) | (hash_outputs[2] >> 24);
  total_preimage_merch[3][12] =  (hash_outputs[2] << 8) | (hash_outputs[3] >> 24);
  total_preimage_merch[3][13] =  (hash_outputs[3] << 8) | (hash_outputs[4] >> 24);
  total_preimage_merch[3][14] =  (hash_outputs[4] << 8) | (hash_outputs[5] >> 24);
  total_preimage_merch[3][15] =  (hash_outputs[5] << 8) | (hash_outputs[6] >> 24);
  total_preimage_merch[4][0]  =  (hash_outputs[6] << 8) | (hash_outputs[7] >> 24);
  total_preimage_merch[4][1]  =  (hash_outputs[7] << 8) | zero;

  total_preimage_merch[4][2]  = one;
//  total_preimage_merch[4][2]  = Integer(32, 1 /*0x00000001*/, PUBLIC);
  total_preimage_merch[4][3]  = eighty;
//  total_preimage_merch[4][3]  = Integer(32, 128 /*0x00000080*/, PUBLIC);

  total_preimage_merch[4][4]   = zero;
  total_preimage_merch[4][5]   = zero;
  total_preimage_merch[4][6]   = zero;
  total_preimage_merch[4][7]   = zero;
  total_preimage_merch[4][8]   = zero;
  total_preimage_merch[4][9]   = zero;
  total_preimage_merch[4][10]  = zero;
  total_preimage_merch[4][11]  = zero;
  total_preimage_merch[4][12]  = zero;
  total_preimage_merch[4][13]  = zero;
  total_preimage_merch[4][14]  = zero;//0x00000000;
  total_preimage_merch[4][15]  = twoonesixeight; // 271*8 = 2168 bits
//  total_preimage_merch[4][15]  = Integer(32, 2168, PUBLIC); // 271*8 = 2168 bits

  computeDoubleSHA256_5d_noinit(total_preimage_merch, merch_digest, k, H, xeight, twofivesix, zero);

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
Bit mask_paytoken(Integer paytoken[8], Mask_d mask, MaskCommitment_d maskcommitment, CommitmentRandomness_d paytoken_mask_commitment_randomness_d, Integer k[64], Integer H[8], Integer xeight, Integer zero, Integer threeeightfour) {

  // The pay token is 256 bits long.
  // Thus the mask is 256 bits long.
  // First we check to see if the mask was correct

  Bit b = verify_mask_commitment(mask, maskcommitment, paytoken_mask_commitment_randomness_d, k, H, xeight, zero, threeeightfour);

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
