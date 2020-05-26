#include "tx-builder.h"
#include <vector>

using namespace std;

struct TxBuilderState {
    Integer output[5][16];
    int outer_pos = 0; //The index of the outer array 0-3
    int inner_pos = 0; //The index of the inner array 0-15
    int sub_pos = 0; //Because a value doesn't have to be perfectly aligned, 0,8,16,24
};

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
    }
    tx_builder->sub_pos = end_shift;
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

void append_tx_start(TxBuilderState* tx_builder, Integer txid1[8], Integer txid2[8], Constants constants) {
    append_constants(tx_builder, vector<Integer>{constants.xzerotwo});
    append_item(tx_builder, constants.zero, constants.zero, 0, txid1, 8, 0);

    append_constants(tx_builder, vector<Integer>{constants.xthreedot, constants.xcdot, constants.xninedot,
                                    constants.xfdot, constants.xfourteendot, constants.xsevendot,
                                    constants.xtwentytwoninedot, constants.xsevenzerosixdot});

    append_item(tx_builder, constants.zero, constants.zero, 0, txid2, 8, 0);

    append_constants(tx_builder, vector<Integer>{constants.zero});
}

// make sure new close transactions are well-formed
void validate_transactions(State_d new_state_d,
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d, PublicKeyHash_d cust_child_publickey_hash_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, BitcoinPublicKey_d merch_payout_pub_key_d,
  PublicKeyHash_d merch_publickey_hash_d, Integer escrow_digest[8], Integer merch_digest[8], Balance_d fee_cc_d, Integer k[64], Integer H[8], Balance_d val_cpfp_d, Constants constants)
{
  //Build output for customer with delay
  TxBuilderState customer_delayed_script_builder;

  //Add revocation lock
  append_item(&customer_delayed_script_builder, constants.xsixthreedot, constants.eighteight, 24, new_state_d.rl.revlock, 8, 0, true);
  //Add merchant dispute key
  append_item(&customer_delayed_script_builder, constants.xtwentyone, constants.sixsevenzero | constants.twohundred, 8, merch_dispute_key_d.key, 9, 0);

  // TODO EMP-6: This previous last byte and the following to bytes is the delay.  We should talk about how long we want them to be
  append_constants(&customer_delayed_script_builder, vector<Integer>{constants.xcfzerofive | constants.btwosevenfive});
  //Add customer payout public key
  append_item(&customer_delayed_script_builder, constants.xtwentyone, constants.sixeightac, 8, cust_payout_pub_key_d.key, 9, 0);

  //Add padding
  append_constants(&customer_delayed_script_builder, vector<Integer>{constants.xeightfirstbyte, constants.zero,
                                                        constants.zero, constants.customerdelayerscriptpreimagelength});

  Integer customer_delayed_script_hash[8];

  // dump_buffer("cust_deplay_script_preimage0=", customer_delayed_script_builder.output[0]);
  // dump_buffer("cust_deplay_script_preimage1=", customer_delayed_script_builder.output[1]);

  computeSHA256_2d_noinit(customer_delayed_script_builder.output, customer_delayed_script_hash, k, H);

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

  //Outputs for cust-close-from-escrow transaction
  TxBuilderState outputs_escrow_builder;
  //Add customer balance output
  append_item(&outputs_escrow_builder, constants.zero, constants.zero, 0, hash_outputs_escrow_little_endian_balance_cust.balance, 2, 0);
  //Add customer output script with delay
  append_item(&outputs_escrow_builder, constants.xtwentytwodot, constants.zero, 24, customer_delayed_script_hash, 8, 24, true);
  //Add merchant balance output
  append_item(&outputs_escrow_builder, constants.zero, constants.sixteen, 0, hash_outputs_escrow_little_endian_balance_merch.balance, 2, 0, true);
  //Add merchant public key
  append_item(&outputs_escrow_builder, constants.xzerozerofourteen, constants.zero, 16, merch_publickey_hash_d.hash, 5, 0, true);
  append_constants(&outputs_escrow_builder, vector<Integer>{constants.zero, constants.threesevensixa});
  //Add revocation lock
  append_item(&outputs_escrow_builder, constants.xfourtyone, constants.zero, 8, new_state_d.rl.revlock, 8, 8, true);
  //Add customer payout public key
  append_item(&outputs_escrow_builder, constants.zero, constants.zero, 0, cust_payout_pub_key_d.key, 9, 16);
  //Add child-pays-for-parent balance
  append_item(&outputs_escrow_builder, constants.zero, constants.xsixteenzerozero, 0, val_cpfp_little_endian.balance, 2, 0, true);
  //Add public key child-pays-for-parent
  append_item(&outputs_escrow_builder, constants.xfourteenzerozero, constants.xeightsecondbyte, 8, cust_child_publickey_hash_d.hash, 5, 0, true);
  append_constants(&outputs_escrow_builder, vector<Integer>{constants.zero, constants.hashoutputspreimagelength});

  Integer hash_outputs_escrow[8];

  computeDoubleSHA256_3d_noinit(outputs_escrow_builder.output, hash_outputs_escrow, k, H, constants);


  //Outputs for cust-close-from-merch transaction
  TxBuilderState outputs_merch_builder;
  //Add customer balance output
  append_item(&outputs_merch_builder, constants.zero, constants.zero, 0, hash_outputs_merch_little_endian_balance_cust.balance, 2, 0);
  //Add customer output script with delay
  append_item(&outputs_merch_builder, constants.xtwentytwodot, constants.zero, 24, customer_delayed_script_hash, 8, 24, true);
  //Add merchant balance output
  append_item(&outputs_merch_builder, constants.zero, constants.sixteen, 0, hash_outputs_merch_little_endian_balance_merch.balance, 2, 0, true);
  //Add merchant public key
  append_item(&outputs_merch_builder, constants.xzerozerofourteen, constants.zero, 16, merch_publickey_hash_d.hash, 5, 0, true);
  append_constants(&outputs_merch_builder, vector<Integer>{constants.zero, constants.threesevensixa});
  //Add revocation lock
  append_item(&outputs_merch_builder, constants.xfourtyone, constants.zero, 8, new_state_d.rl.revlock, 8, 8, true);
  //Add customer payout public key
  append_item(&outputs_merch_builder, constants.zero, constants.zero, 0, cust_payout_pub_key_d.key, 9, 16);
  //Add child-pays-for-parent balance
  append_item(&outputs_merch_builder, constants.zero, constants.xsixteenzerozero, 0, val_cpfp_little_endian.balance, 2, 0, true);
  //Add public key child-pays-for-parent
  append_item(&outputs_merch_builder, constants.xfourteenzerozero, constants.xeightsecondbyte, 8, cust_child_publickey_hash_d.hash, 5, 0, true);
  append_constants(&outputs_merch_builder, vector<Integer>{constants.zero, constants.hashoutputspreimagelength});

  Integer hash_outputs_merch[8];

  computeDoubleSHA256_3d_noinit(outputs_merch_builder.output, hash_outputs_merch, k, H, constants);


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
}