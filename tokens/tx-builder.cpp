#include "tx-builder.h"
#include <vector>

using namespace std;

struct TxBuilderState {
    Integer output[5][16];
    int outer_pos; //The index of the outer array 0-3
    int inner_pos; //The index of the inner array 0-15
    int sub_pos; //Because a value doesn't have to be perfectly aligned, 0,8,16,24
};

void append_tx_start(TxBuilderState* tx_builder, Integer txid1[8], Integer txid2[8], Constants constants) {
    tx_builder->output[0][0] = constants.xzerotwo; /*0x02000000*/

    for (int i=0;i<8; i++) {
        tx_builder->output[0][i+1] = txid1[i];
    }

    tx_builder->output[0][9]  =  constants.xthreedot;          /*0x3bb13029*/
    tx_builder->output[0][10] =  constants.xcdot;              /*0xce7b1f55*/
    tx_builder->output[0][11] =  constants.xninedot;           /*0x9ef5e747*/
    tx_builder->output[0][12] =  constants.xfdot;              /*0xfcac439f*/
    tx_builder->output[0][13] =  constants.xfourteendot;       /*0x1455a2ec*/
    tx_builder->output[0][14] =  constants.xsevendot;          /*0x7c5f09b7*/
    tx_builder->output[0][15] =  constants.xtwentytwoninedot;  /*0x2290795e*/
    tx_builder->output[1][0]  =  constants.xsevenzerosixdot;   /*0x70665044*/

    for (int i=0;i<8; i++) {
        tx_builder->output[1][i+1] = txid2[i];
    }

    tx_builder->output[1][9] = constants.zero;
    tx_builder->outer_pos = 1;
    tx_builder->inner_pos = 10;
    tx_builder->sub_pos = 0;
}

void append_item(TxBuilderState* tx_builder, Integer front_padding, Integer back_padding, int sub_pos, Integer* item, int size, int end_shift, bool overflow=false) {
    int i = tx_builder->outer_pos;
    int j = tx_builder->inner_pos;
    int sub = sub_pos + tx_builder->sub_pos;
    int inv_sub_pos = 32 - sub;
    if (tx_builder->sub_pos == 0) {
        tx_builder->output[i][j] = front_padding | (item[0] >> sub);
    } else {
        tx_builder->output[i][j] = tx_builder->output[i][j] | (item[0] >> sub);
    }
    if (j == 15) {
        i++;
    }
    j = (j + 1) % 16;
    int nr_of_it = size - 1;
    if (overflow) {
        nr_of_it = size;
    }
    for (int k = 1; k < nr_of_it; k++) {
        tx_builder->output[i][j] = (item[k-1] << inv_sub_pos) | (item[k] >> sub);
        if (j == 15) {
            i++;
        }
        j = (j + 1) % 16;
    }
    if (overflow) {
        tx_builder->output[i][j] = (item[size-1] << inv_sub_pos) | back_padding;
    } else {
        tx_builder->output[i][j] = (item[size-2] << inv_sub_pos) | (item[size-1] >> sub) | back_padding;
    }

    if (end_shift == 0) {
        if (j == 15) {
            i++;
        }
        j = (j + 1) % 16;
        tx_builder->sub_pos = 0;
    } else {
        tx_builder->sub_pos = end_shift;
    }


    tx_builder->outer_pos = i;
    tx_builder->inner_pos = j;
}

void append_constants(TxBuilderState* tx_builder, vector<Integer> constants_in) {
    int i = tx_builder->outer_pos;
    int j = tx_builder->inner_pos;
    for (Integer con : constants_in) {
        tx_builder->output[i][j] = con;
        if (j == 15) {
            i++;
        }
        j = (j + 1) % 16;
    }
    tx_builder->outer_pos = i;
    tx_builder->inner_pos = j;
}

// make sure new close transactions are well-formed
void validate_transactions(State_d new_state_d,
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d, PublicKeyHash_d cust_child_publickey_hash_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, BitcoinPublicKey_d merch_payout_pub_key_d,
  PublicKeyHash_d merch_publickey_hash_d, Integer escrow_digest[8], Integer merch_digest[8], Balance_d fee_cc_d, Integer k[64], Integer H[8], Balance_d val_cpfp_d, Constants constants)
{
  // 112 bytes --> 896
  Integer customer_delayed_script_hash_preimage[2][16];

  // OPCODE || 1 byte of Rev Lock  0x63a82000  1671962624
  customer_delayed_script_hash_preimage[0][0] = constants.xsixthreedot | /* First byte of revlock*/(new_state_d.rl.revlock[0] >> 24);
//  customer_delayed_script_hash_preimage[0][0] = Integer(32, 1671962624 /*0x63a92000*/, PUBLIC) | /* First byte of revlock*/(new_state_d.rl.revlock[0] >> 24);

  // 31 remaining bytes of Rev Lock
  customer_delayed_script_hash_preimage[0][1] = (/* last 3 bytes */ new_state_d.rl.revlock[0] << 8) | ( /* first byte of the next int */ new_state_d.rl.revlock[1] >> 24);
  customer_delayed_script_hash_preimage[0][2] = (new_state_d.rl.revlock[1] << 8) | (new_state_d.rl.revlock[2] >> 24);
  customer_delayed_script_hash_preimage[0][3] = (new_state_d.rl.revlock[2] << 8) | (new_state_d.rl.revlock[3] >> 24);
  customer_delayed_script_hash_preimage[0][4] = (new_state_d.rl.revlock[3] << 8) | (new_state_d.rl.revlock[4] >> 24);
  customer_delayed_script_hash_preimage[0][5] = (new_state_d.rl.revlock[4] << 8) | (new_state_d.rl.revlock[5] >> 24);
  customer_delayed_script_hash_preimage[0][6] = (new_state_d.rl.revlock[5] << 8) | (new_state_d.rl.revlock[6] >> 24);
  customer_delayed_script_hash_preimage[0][7] = (new_state_d.rl.revlock[6] << 8) | (new_state_d.rl.revlock[7] >> 24);
  customer_delayed_script_hash_preimage[0][8] = (new_state_d.rl.revlock[7] << 8) | constants.eighteight;
//  customer_delayed_script_hash_preimage[0][8] = (new_state_d.rl.revlock[7] << 8) | Integer(32, 136 /*0x00000088*/, PUBLIC);

  customer_delayed_script_hash_preimage[0][9]  = constants.xtwentyone | merch_dispute_key_d.key[0] >> 8; //0x21000000 // taking 3 bytes from the key
//  customer_delayed_script_hash_preimage[0][9]  = Integer(32, 553648128, PUBLIC) | merch_dispute_key_d.key[0] >> 8; //0x21000000 // taking 3 bytes from the key
  customer_delayed_script_hash_preimage[0][10] = (merch_dispute_key_d.key[0] << 24) | (merch_dispute_key_d.key[1] >> 8); // byte 4-7
  customer_delayed_script_hash_preimage[0][11] = (merch_dispute_key_d.key[1] << 24) | (merch_dispute_key_d.key[2] >> 8); // byte 8-11
  customer_delayed_script_hash_preimage[0][12] = (merch_dispute_key_d.key[2] << 24) | (merch_dispute_key_d.key[3] >> 8); // bytes 12-15
  customer_delayed_script_hash_preimage[0][13] = (merch_dispute_key_d.key[3] << 24) | (merch_dispute_key_d.key[4] >> 8); // bytes 16-19
  customer_delayed_script_hash_preimage[0][14] = (merch_dispute_key_d.key[4] << 24) | (merch_dispute_key_d.key[5] >> 8); // bytes 20-23
  customer_delayed_script_hash_preimage[0][15] = (merch_dispute_key_d.key[5] << 24) | (merch_dispute_key_d.key[6] >> 8); // bytes 24-27
  customer_delayed_script_hash_preimage[1][0]  = (merch_dispute_key_d.key[6] << 24) | (merch_dispute_key_d.key[7] >> 8); // bytes 28-31
  customer_delayed_script_hash_preimage[1][1]  = (merch_dispute_key_d.key[7] << 24) | (merch_dispute_key_d.key[8] >> 8) | constants.sixsevenzero | constants.twohundred; // bytes 32-33 // 0x67
//  customer_delayed_script_hash_preimage[1][1]  = (merch_dispute_key_d.key[7] << 24) | (merch_dispute_key_d.key[8] >> 8) | Integer(32, 26368/*0x00006700*/, PUBLIC) | Integer(32,2 /*0x000002*/, PUBLIC); // bytes 32-33 // 0x67

  // This previous last byte and the following to bytes is the delay.  We should talk about how long we want them to be
  customer_delayed_script_hash_preimage[1][2]  = constants.xcfzerofive | constants.btwosevenfive;
//  customer_delayed_script_hash_preimage[1][2]  = Integer(32, 3473211392 /*0xcf050000*/, PUBLIC) | Integer(32, 45685/*0x0000b275*/, PUBLIC);
  customer_delayed_script_hash_preimage[1][3]  = constants.xtwentyone  | (cust_payout_pub_key_d.key[0] >> 8);
//  customer_delayed_script_hash_preimage[1][3]  = Integer(32, 553648128 /*0x21000000*/, PUBLIC)  | (cust_payout_pub_key_d.key[0] >> 8);
  customer_delayed_script_hash_preimage[1][4]  = (cust_payout_pub_key_d.key[0] << 24) | (cust_payout_pub_key_d.key[1] >> 8);
  customer_delayed_script_hash_preimage[1][5]  = (cust_payout_pub_key_d.key[1] << 24) | (cust_payout_pub_key_d.key[2] >> 8);
  customer_delayed_script_hash_preimage[1][6]  = (cust_payout_pub_key_d.key[2] << 24) | (cust_payout_pub_key_d.key[3] >> 8);
  customer_delayed_script_hash_preimage[1][7]  = (cust_payout_pub_key_d.key[3] << 24) | (cust_payout_pub_key_d.key[4] >> 8);
  customer_delayed_script_hash_preimage[1][8]  = (cust_payout_pub_key_d.key[4] << 24) | (cust_payout_pub_key_d.key[5] >> 8);
  customer_delayed_script_hash_preimage[1][9]  = (cust_payout_pub_key_d.key[5] << 24) | (cust_payout_pub_key_d.key[6] >> 8);
  customer_delayed_script_hash_preimage[1][10] = (cust_payout_pub_key_d.key[6] << 24) | (cust_payout_pub_key_d.key[7] >> 8);
  customer_delayed_script_hash_preimage[1][11] = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | constants.sixeightac;
//  customer_delayed_script_hash_preimage[1][11] = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | Integer(32, 26796/*0x000068ac*/, PUBLIC);

  customer_delayed_script_hash_preimage[1][12] = constants.xeightfirstbyte;
//  customer_delayed_script_hash_preimage[1][12] = Integer(32, -2147483648/*0x80000000*/, PUBLIC);
  customer_delayed_script_hash_preimage[1][13] = constants.zero; //0x00000000;
  customer_delayed_script_hash_preimage[1][14] = constants.zero; //0x00000000;
  customer_delayed_script_hash_preimage[1][15] = constants.customerdelayerscriptpreimagelength;
//  customer_delayed_script_hash_preimage[1][15] = Integer(32, 896, PUBLIC);

  Integer customer_delayed_script_hash[8];

  // dump_buffer("cust_deplay_script_preimage0=", customer_delayed_script_hash_preimage[0]);
  // dump_buffer("cust_deplay_script_preimage1=", customer_delayed_script_hash_preimage[1]);

  computeSHA256_2d_noinit(customer_delayed_script_hash_preimage, customer_delayed_script_hash, k, H);

  // Doing math for the balance
  // For reference, see https://docs.google.com/document/d/1It_WOpSwUuZnuhVtyVJLXAHrZCsEy21o7ZiDqkVzYY4/edit#bookmark=id.p25f1i42y4ov
  // For the cust close from escrow tx, we want
  //  b_c - val_cpfp - fee_cc
  //  b_m
  //  val_cpdp
  // For the cust close from merch close tx we want
  //  b_c - val_cpfp - fee_cc
  //  b_m - fee_mc - val_cpfp
  //  val_cpdp

  Integer cust_balance_in_state_combined = combine_balance(new_state_d.balance_cust);
  Integer merch_balance_in_state_combined = combine_balance(new_state_d.balance_merch);
  Integer val_cpfp_combined = combine_balance(val_cpfp_d);
  Integer fee_cc_combined = combine_balance(fee_cc_d);
  Integer fee_mc_combined = combine_balance(new_state_d.fee_mc);

  Integer hash_outputs_escrow_cust_balance = cust_balance_in_state_combined - val_cpfp_combined - fee_cc_combined;
  Integer hash_outputs_escrow_merch_balance = merch_balance_in_state_combined;

  Integer hash_outputs_merch_cust_balance = cust_balance_in_state_combined - val_cpfp_combined - fee_cc_combined;
  Integer hash_outputs_merch_merch_balance = merch_balance_in_state_combined - val_cpfp_combined - fee_mc_combined;


  Balance_d hash_outputs_escrow_little_endian_balance_cust = convert_to_little_endian(split_integer_to_balance(hash_outputs_escrow_cust_balance, constants.fullFsixtyfour), constants);
  Balance_d hash_outputs_escrow_little_endian_balance_merch = convert_to_little_endian(split_integer_to_balance(hash_outputs_escrow_merch_balance, constants.fullFsixtyfour), constants);

  Balance_d hash_outputs_merch_little_endian_balance_cust = convert_to_little_endian(split_integer_to_balance(hash_outputs_merch_cust_balance, constants.fullFsixtyfour), constants);
  Balance_d hash_outputs_merch_little_endian_balance_merch = convert_to_little_endian(split_integer_to_balance(hash_outputs_merch_merch_balance, constants.fullFsixtyfour), constants);

  Balance_d val_cpfp_little_endian = convert_to_little_endian(val_cpfp_d, constants);
  // TODO finish maths


  Integer hash_outputs_escrow_preimage[3][16];

  hash_outputs_escrow_preimage[0][0]  = hash_outputs_escrow_little_endian_balance_cust.balance[0];// first bytes of customer balance // FIX ENDIANNESS
  hash_outputs_escrow_preimage[0][1]  = hash_outputs_escrow_little_endian_balance_cust.balance[1];// second bytes of customer blanace // FIX ENDIANNESS

  hash_outputs_escrow_preimage[0][2]  = constants.xtwentytwodot | (customer_delayed_script_hash[0] >> 24); // OPCODE and the first byte of the prev hash output
//  hash_outputs_escrow_preimage[0][2]  = Integer(32, 570433536 /*0x22002000*/, PUBLIC) | (customer_delayed_script_hash[0] >> 24); // OPCODE and the first byte of the prev hash output
  hash_outputs_escrow_preimage[0][3]  = (customer_delayed_script_hash[0] << 8) | (customer_delayed_script_hash[1] >> 24); // end of byte 1 and first byte of 2...
  hash_outputs_escrow_preimage[0][4]  = (customer_delayed_script_hash[1] << 8) | (customer_delayed_script_hash[2] >> 24);
  hash_outputs_escrow_preimage[0][5]  = (customer_delayed_script_hash[2] << 8) | (customer_delayed_script_hash[3] >> 24);
  hash_outputs_escrow_preimage[0][6]  = (customer_delayed_script_hash[3] << 8) | (customer_delayed_script_hash[4] >> 24);
  hash_outputs_escrow_preimage[0][7]  = (customer_delayed_script_hash[4] << 8) | (customer_delayed_script_hash[5] >> 24);
  hash_outputs_escrow_preimage[0][8]  = (customer_delayed_script_hash[5] << 8) | (customer_delayed_script_hash[6] >> 24);
  hash_outputs_escrow_preimage[0][9]  = (customer_delayed_script_hash[6] << 8) | (customer_delayed_script_hash[7] >> 24);
  hash_outputs_escrow_preimage[0][10] = (customer_delayed_script_hash[7] << 8) |  (hash_outputs_escrow_little_endian_balance_merch.balance[0] >> 24);/*first byte of merch balance >> 24*/;
  hash_outputs_escrow_preimage[0][11] =  (hash_outputs_escrow_little_endian_balance_merch.balance[0] << 8) | (hash_outputs_escrow_little_endian_balance_merch.balance[1] >> 24);
  hash_outputs_escrow_preimage[0][12] =  (hash_outputs_escrow_little_endian_balance_merch.balance[1] << 8) | constants.sixteen;
//  hash_outputs_escrow_preimage[0][12] =  (little_endian_balance_merch.balance[1] << 8) | Integer(32, 22 /*0x00000016*/, PUBLIC);
  hash_outputs_escrow_preimage[0][13] = constants.xzerozerofourteen | (merch_publickey_hash_d.hash[0] >> 16);
//  hash_outputs_escrow_preimage[0][13] = Integer(32, 1310720 /*0x00140000*/, PUBLIC) | (merch_publickey_hash_d.hash[0] >> 16);
  hash_outputs_escrow_preimage[0][14] = (merch_publickey_hash_d.hash[0] << 16) | (merch_publickey_hash_d.hash[1] >> 16);
  hash_outputs_escrow_preimage[0][15] = (merch_publickey_hash_d.hash[1] << 16) | (merch_publickey_hash_d.hash[2] >> 16);
  hash_outputs_escrow_preimage[1][0]  = (merch_publickey_hash_d.hash[2] << 16) | (merch_publickey_hash_d.hash[3] >> 16);
  hash_outputs_escrow_preimage[1][1]  = (merch_publickey_hash_d.hash[3] << 16) | (merch_publickey_hash_d.hash[4] >> 16);
  hash_outputs_escrow_preimage[1][2]  = (merch_publickey_hash_d.hash[4] << 16) | constants.zero; //Two bytes of the OP_Return Amount
  hash_outputs_escrow_preimage[1][3]  = constants.zero; // middle 4 bytes of OP_RETURN amount
  hash_outputs_escrow_preimage[1][4]  = constants.threesevensixa; // OPRETURN FORMATTING
//  hash_outputs_escrow_preimage[1][4]  = Integer(32, 17258/*0x0000376a*/,PUBLIC); // OPRETURN FORMATTING
  hash_outputs_escrow_preimage[1][5] = constants.xfourtyone /*last byte of opreturn formatting */ | (new_state_d.rl.revlock[0] >> 8);
//  hash_outputs_escrow_preimage[1][5] = Integer(32, 1090519040/*0x41000000*/,PUBLIC)/*last byte of opreturn formatting */ | (new_state_d.rl.revlock[0] >> 8);

  hash_outputs_escrow_preimage[1][6]  = (new_state_d.rl.revlock[0] << 24) | (new_state_d.rl.revlock[1] >> 8);
  hash_outputs_escrow_preimage[1][7]  = (new_state_d.rl.revlock[1] << 24) | (new_state_d.rl.revlock[2] >> 8);
  hash_outputs_escrow_preimage[1][8]  = (new_state_d.rl.revlock[2] << 24) | (new_state_d.rl.revlock[3] >> 8);
  hash_outputs_escrow_preimage[1][9]  = (new_state_d.rl.revlock[3] << 24) | (new_state_d.rl.revlock[4] >> 8);
  hash_outputs_escrow_preimage[1][10]  = (new_state_d.rl.revlock[4] << 24) | (new_state_d.rl.revlock[5] >> 8);
  hash_outputs_escrow_preimage[1][11] = (new_state_d.rl.revlock[5] << 24) | (new_state_d.rl.revlock[6] >> 8);
  hash_outputs_escrow_preimage[1][12] = (new_state_d.rl.revlock[6] << 24) | (new_state_d.rl.revlock[7] >> 8);
  hash_outputs_escrow_preimage[1][13] = (new_state_d.rl.revlock[7] << 24) | (cust_payout_pub_key_d.key[0] >> 8); //1
  hash_outputs_escrow_preimage[1][14] = (cust_payout_pub_key_d.key[0] << 24) | (cust_payout_pub_key_d.key[1] >> 8); //5
  hash_outputs_escrow_preimage[1][15] = (cust_payout_pub_key_d.key[1] << 24) | (cust_payout_pub_key_d.key[2] >> 8); //9
  hash_outputs_escrow_preimage[2][0] = (cust_payout_pub_key_d.key[2] << 24) | (cust_payout_pub_key_d.key[3] >> 8); //13
  hash_outputs_escrow_preimage[2][1]  = (cust_payout_pub_key_d.key[3] << 24) | (cust_payout_pub_key_d.key[4] >> 8); //17
  hash_outputs_escrow_preimage[2][2]  = (cust_payout_pub_key_d.key[4] << 24) | (cust_payout_pub_key_d.key[5] >> 8); //21
  hash_outputs_escrow_preimage[2][3]  = (cust_payout_pub_key_d.key[5] << 24) | (cust_payout_pub_key_d.key[6] >> 8); //25
  hash_outputs_escrow_preimage[2][4]  = (cust_payout_pub_key_d.key[6] << 24) | (cust_payout_pub_key_d.key[7] >> 8); //29
  hash_outputs_escrow_preimage[2][5]  = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | (val_cpfp_little_endian.balance[0] >> 16); //33

  hash_outputs_escrow_preimage[2][6]  = (val_cpfp_little_endian.balance[0] << 16) | (val_cpfp_little_endian.balance[1] >> 16);
  hash_outputs_escrow_preimage[2][7]  = (val_cpfp_little_endian.balance[1] << 16) | constants.xsixteenzerozero;
  hash_outputs_escrow_preimage[2][8]  = constants.xfourteenzerozero | (cust_child_publickey_hash_d.hash[0] >> 8);
  hash_outputs_escrow_preimage[2][9]  = (cust_child_publickey_hash_d.hash[0] << 24) | (cust_child_publickey_hash_d.hash[1] >> 8);
  hash_outputs_escrow_preimage[2][10] = (cust_child_publickey_hash_d.hash[1] << 24) | (cust_child_publickey_hash_d.hash[2] >> 8);
  hash_outputs_escrow_preimage[2][11] = (cust_child_publickey_hash_d.hash[2] << 24) | (cust_child_publickey_hash_d.hash[3] >> 8);
  hash_outputs_escrow_preimage[2][12] = (cust_child_publickey_hash_d.hash[3] << 24) | (cust_child_publickey_hash_d.hash[4] >> 8);

  hash_outputs_escrow_preimage[2][13] =  (cust_child_publickey_hash_d.hash[4] << 24) | constants.xeightsecondbyte;
  hash_outputs_escrow_preimage[2][14] = constants.zero; //0x00000000;
  hash_outputs_escrow_preimage[2][15] = constants.hashoutputspreimagelength;

  Integer hash_outputs_escrow[8];


  computeDoubleSHA256_3d_noinit(hash_outputs_escrow_preimage, hash_outputs_escrow, k, H, constants);


  Integer hash_outputs_merch_preimage[3][16];

  hash_outputs_merch_preimage[0][0]  = hash_outputs_merch_little_endian_balance_cust.balance[0];// first bytes of customer balance // FIX ENDIANNESS
  hash_outputs_merch_preimage[0][1]  = hash_outputs_merch_little_endian_balance_cust.balance[1];// second bytes of customer blanace // FIX ENDIANNESS

  hash_outputs_merch_preimage[0][2]  = constants.xtwentytwodot | (customer_delayed_script_hash[0] >> 24); // OPCODE and the first byte of the prev hash output
//  hash_outputs_merch_preimage[0][2]  = Integer(32, 570433536 /*0x22002000*/, PUBLIC) | (customer_delayed_script_hash[0] >> 24); // OPCODE and the first byte of the prev hash output
  hash_outputs_merch_preimage[0][3]  = (customer_delayed_script_hash[0] << 8) | (customer_delayed_script_hash[1] >> 24); // end of byte 1 and first byte of 2...
  hash_outputs_merch_preimage[0][4]  = (customer_delayed_script_hash[1] << 8) | (customer_delayed_script_hash[2] >> 24);
  hash_outputs_merch_preimage[0][5]  = (customer_delayed_script_hash[2] << 8) | (customer_delayed_script_hash[3] >> 24);
  hash_outputs_merch_preimage[0][6]  = (customer_delayed_script_hash[3] << 8) | (customer_delayed_script_hash[4] >> 24);
  hash_outputs_merch_preimage[0][7]  = (customer_delayed_script_hash[4] << 8) | (customer_delayed_script_hash[5] >> 24);
  hash_outputs_merch_preimage[0][8]  = (customer_delayed_script_hash[5] << 8) | (customer_delayed_script_hash[6] >> 24);
  hash_outputs_merch_preimage[0][9]  = (customer_delayed_script_hash[6] << 8) | (customer_delayed_script_hash[7] >> 24);
  hash_outputs_merch_preimage[0][10] = (customer_delayed_script_hash[7] << 8) |  (hash_outputs_merch_little_endian_balance_merch.balance[0] >> 24);/*first byte of merch balance >> 24*/;
  hash_outputs_merch_preimage[0][11] =  (hash_outputs_merch_little_endian_balance_merch.balance[0] << 8) | (hash_outputs_merch_little_endian_balance_merch.balance[1] >> 24);
  hash_outputs_merch_preimage[0][12] =  (hash_outputs_merch_little_endian_balance_merch.balance[1] << 8) | constants.sixteen;
//  hash_outputs_merch_preimage[0][12] =  (little_endian_balance_merch.balance[1] << 8) | Integer(32, 22 /*0x00000016*/, PUBLIC);
  hash_outputs_merch_preimage[0][13] = constants.xzerozerofourteen | (merch_publickey_hash_d.hash[0] >> 16);
//  hash_outputs_merch_preimage[0][13] = Integer(32, 1310720 /*0x00140000*/, PUBLIC) | (merch_publickey_hash_d.hash[0] >> 16);
  hash_outputs_merch_preimage[0][14] = (merch_publickey_hash_d.hash[0] << 16) | (merch_publickey_hash_d.hash[1] >> 16);
  hash_outputs_merch_preimage[0][15] = (merch_publickey_hash_d.hash[1] << 16) | (merch_publickey_hash_d.hash[2] >> 16);
  hash_outputs_merch_preimage[1][0]  = (merch_publickey_hash_d.hash[2] << 16) | (merch_publickey_hash_d.hash[3] >> 16);
  hash_outputs_merch_preimage[1][1]  = (merch_publickey_hash_d.hash[3] << 16) | (merch_publickey_hash_d.hash[4] >> 16);
  hash_outputs_merch_preimage[1][2]  = (merch_publickey_hash_d.hash[4] << 16) | constants.zero; //Two bytes of the OP_Return Amount
  hash_outputs_merch_preimage[1][3]  = constants.zero; // middle 4 bytes of OP_RETURN amount
  hash_outputs_merch_preimage[1][4]  = constants.threesevensixa; // OPRETURN FORMATTING
//  hash_outputs_merch_preimage[1][4]  = Integer(32, 17258/*0x0000376a*/,PUBLIC); // OPRETURN FORMATTING
  hash_outputs_merch_preimage[1][5] = constants.xfourtyone /*last byte of opreturn formatting */ | (new_state_d.rl.revlock[0] >> 8);
//  hash_outputs_merch_preimage[1][5] = Integer(32, 1090519040/*0x41000000*/,PUBLIC)/*last byte of opreturn formatting */ | (new_state_d.rl.revlock[0] >> 8);

  hash_outputs_merch_preimage[1][6]  = (new_state_d.rl.revlock[0] << 24) | (new_state_d.rl.revlock[1] >> 8);
  hash_outputs_merch_preimage[1][7]  = (new_state_d.rl.revlock[1] << 24) | (new_state_d.rl.revlock[2] >> 8);
  hash_outputs_merch_preimage[1][8]  = (new_state_d.rl.revlock[2] << 24) | (new_state_d.rl.revlock[3] >> 8);
  hash_outputs_merch_preimage[1][9]  = (new_state_d.rl.revlock[3] << 24) | (new_state_d.rl.revlock[4] >> 8);
  hash_outputs_merch_preimage[1][10] = (new_state_d.rl.revlock[4] << 24) | (new_state_d.rl.revlock[5] >> 8);
  hash_outputs_merch_preimage[1][11] = (new_state_d.rl.revlock[5] << 24) | (new_state_d.rl.revlock[6] >> 8);
  hash_outputs_merch_preimage[1][12] = (new_state_d.rl.revlock[6] << 24) | (new_state_d.rl.revlock[7] >> 8);
  hash_outputs_merch_preimage[1][13] = (new_state_d.rl.revlock[7] << 24) | (cust_payout_pub_key_d.key[0] >> 8); //1
  hash_outputs_merch_preimage[1][14] = (cust_payout_pub_key_d.key[0] << 24) | (cust_payout_pub_key_d.key[1] >> 8); //5
  hash_outputs_merch_preimage[1][15] = (cust_payout_pub_key_d.key[1] << 24) | (cust_payout_pub_key_d.key[2] >> 8); //9
  hash_outputs_merch_preimage[2][0]  = (cust_payout_pub_key_d.key[2] << 24) | (cust_payout_pub_key_d.key[3] >> 8); //13
  hash_outputs_merch_preimage[2][1]  = (cust_payout_pub_key_d.key[3] << 24) | (cust_payout_pub_key_d.key[4] >> 8); //17
  hash_outputs_merch_preimage[2][2]  = (cust_payout_pub_key_d.key[4] << 24) | (cust_payout_pub_key_d.key[5] >> 8); //21
  hash_outputs_merch_preimage[2][3]  = (cust_payout_pub_key_d.key[5] << 24) | (cust_payout_pub_key_d.key[6] >> 8); //25
  hash_outputs_merch_preimage[2][4]  = (cust_payout_pub_key_d.key[6] << 24) | (cust_payout_pub_key_d.key[7] >> 8); //29
  hash_outputs_merch_preimage[2][5]  = (cust_payout_pub_key_d.key[7] << 24) | (cust_payout_pub_key_d.key[8] >> 8) | (val_cpfp_little_endian.balance[0] >> 16); //33

  hash_outputs_merch_preimage[2][6]  = (val_cpfp_little_endian.balance[0] << 16) | (val_cpfp_little_endian.balance[1] >> 16);
  hash_outputs_merch_preimage[2][7]  = (val_cpfp_little_endian.balance[1] << 16) | constants.xsixteenzerozero;
  hash_outputs_merch_preimage[2][8]  = constants.xfourteenzerozero | (cust_child_publickey_hash_d.hash[0] >> 8);
  hash_outputs_merch_preimage[2][9]  = (cust_child_publickey_hash_d.hash[0] << 24) | (cust_child_publickey_hash_d.hash[1] >> 8);
  hash_outputs_merch_preimage[2][10] = (cust_child_publickey_hash_d.hash[1] << 24) | (cust_child_publickey_hash_d.hash[2] >> 8);
  hash_outputs_merch_preimage[2][11] = (cust_child_publickey_hash_d.hash[2] << 24) | (cust_child_publickey_hash_d.hash[3] >> 8);
  hash_outputs_merch_preimage[2][12] = (cust_child_publickey_hash_d.hash[3] << 24) | (cust_child_publickey_hash_d.hash[4] >> 8);

  hash_outputs_merch_preimage[2][13] =  (cust_child_publickey_hash_d.hash[4] << 24) | constants.xeightsecondbyte;
  hash_outputs_merch_preimage[2][14] = constants.zero; //0x00000000;
  hash_outputs_merch_preimage[2][15] = constants.hashoutputspreimagelength;

  Integer hash_outputs_merch[8];

  computeDoubleSHA256_3d_noinit(hash_outputs_merch_preimage, hash_outputs_merch, k, H, constants);


  //START -----cust-close-from-escrow transaction-----
  TxBuilderState tx_builder_escrow;
  //Start cust-close-from-escrow transaction with input tx id and own tx id
  append_tx_start(&tx_builder_escrow, new_state_d.HashPrevOuts_escrow.txid, new_state_d.txid_escrow.txid, constants);
  //Add merchant public key to cust-close-from-escrow transaction
  append_item(&tx_builder_escrow, constants.xfoursevenfivedot, constants.zero, 24, merch_escrow_pub_key_d.key, 9, 0);
  //Add customer public key to cust-close-from-escrow transaction
  append_item(&tx_builder_escrow, constants.xtwentyone, constants.fivetwoae, 8, cust_escrow_pub_key_d.key, 9, 0);

  Balance_d big_endian_total_amount = split_integer_to_balance(cust_balance_in_state_combined + merch_balance_in_state_combined, constants.fullFsixtyfour);
  Balance_d little_endian_total_amount = convert_to_little_endian(big_endian_total_amount, constants);
  //Add total output balance to cust-close-from-escrow transaction
  append_item(&tx_builder_escrow, constants.zero, constants.zero, 0, little_endian_total_amount.balance, 2, 0);

  append_constants(&tx_builder_escrow, vector<Integer>{constants.fullFthirtytwo});

  //Add hash of outputs to cust-close-from-escrow transaction
  append_item(&tx_builder_escrow, constants.zero, constants.zero, 0, hash_outputs_escrow, 8, 0);
  //Add padding to cust-close-from-escrow transaction
  append_constants(&tx_builder_escrow, vector<Integer>{constants.zero, constants.xzeroone, constants.xeightfirstbyte,
                    constants.zero, constants.zero, constants.zero, constants.zero,
                    constants.zero, constants.escrowtransactionpreimagelength});


  //Compute Hash of transaction
  computeDoubleSHA256_4d_noinit(tx_builder_escrow.output, escrow_digest, k, H, constants);
  //END -----cust-close-from-escrow transaction-----

  //START ----cust-close-from-merch transaction-----
  TxBuilderState tx_builder_merch;
  //Start cust-close-from-merch transaction with input tx id and own tx id
  append_tx_start(&tx_builder_merch, new_state_d.HashPrevOuts_merch.txid, new_state_d.txid_merch.txid, constants);

  // The script
  append_constants(&tx_builder_merch, vector<Integer>{constants.xseventwosixdot});
  //Add merchant public key to cust-close-from-merch transaction
  append_item(&tx_builder_merch, constants.zero, constants.xzerozerotwentyone, 0, merch_escrow_pub_key_d.key, 9, 16);

  //Add customer public key to cust-close-from-merch transaction
  append_item(&tx_builder_merch, constants.zero, constants.fiftytwo, 0, cust_escrow_pub_key_d.key, 9, 0);

  append_constants(&tx_builder_merch, vector<Integer>{constants.xaedot, constants.xzerofivedot});

  // Add merch-payout-key to cust-close-from-merch transaction
  append_item(&tx_builder_merch, constants.zero, constants.acsixeightzerozero, 0, merch_payout_pub_key_d.key, 9, 24);
  // Add total amount to cust-close-from-merch transaction
  Balance_d big_endian_total_amount_merch = split_integer_to_balance(cust_balance_in_state_combined + merch_balance_in_state_combined, constants.fullFsixtyfour);
  Balance_d little_endian_total_amount_merch = convert_to_little_endian(big_endian_total_amount_merch, constants);
  append_item(&tx_builder_merch, constants.zero, constants.ff, 0, little_endian_total_amount_merch.balance, 2, 0, true);

  //Add hash of output script to cust-close-from-merch transaction
  append_item(&tx_builder_merch, constants.ffffffzerozero, constants.zero, 24, hash_outputs_merch, 8, 0, true);
  //Add padding to cust-close-from-merch transaction
  append_constants(&tx_builder_merch, vector<Integer>{constants.one,constants.xeightfourthbyte,
                    constants.zero, constants.zero, constants.zero, constants.zero, constants.zero,
                    constants.zero, constants.zero, constants.zero, constants.zero, constants.zero,
                    constants.zero, constants.merchtransactionpreimagelength});

  computeDoubleSHA256_5d_noinit(tx_builder_merch.output, merch_digest, k, H, constants);
  //END -----cust-close-from-merch transaction-----

//   dump_buffer("hash_outputs_merch_preimage0=", hash_outputs_merch_preimage[0]);
//   dump_buffer("hash_outputs_merch_preimage1=", hash_outputs_merch_preimage[1]);
//   dump_buffer("hash_outputs_merch_preimage2=", hash_outputs_merch_preimage[2]);

//   dump_buffer("hash_outputs_escrow_preimage0=", hash_outputs_escrow_preimage[0]);
//   dump_buffer("hash_outputs_escrow_preimage1=", hash_outputs_escrow_preimage[1]);
//   dump_buffer("hash_outputs_escrow_preimage2=", hash_outputs_escrow_preimage[2]);

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