#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
#include "constants.h"
using namespace emp;

typedef struct PreimageBuilderState PreimageBuilderState;
struct PreimageBuilderState {
  int BytesSoFar;
};


void append_item(Integer buffer[2][16], PreimageBuilderState state, BitcoinPublicKey_d publickey_d);

void append_item(Integer buffer[2][16], PreimageBuilderState state, RevLock_d rl_d);

void append_item(Integer buffer[2][16], PreimageBuilderState state, Balance_d balance_d);

void fill_buffer(Integer buffer[2][16], PreimageBuilderState state, Integer lengthChunk);



void append_item(Integer buffer[3][16], PreimageBuilderState state, Balance_d balance_d);

void append_item(Integer buffer[3][16], PreimageBuilderState state, Integer[8] hash_d);

void append_item(Integer buffer[3][16], PreimageBuilderState state, PublicKeyHash_d merch_publickey_hash_d);

void append_item(Integer buffer[3][16], PreimageBuilderState state, RevLock_d rl_d);

void append_item(Integer buffer[3][16], PreimageBuilderState state, BitcoinPublicKey_d publickey_d);

void fill_buffer(Integer buffer[3][16], PreimageBuilderState state, Integer lengthChunk);




void append_item(Integer buffer[4][16], PreimageBuilderState state, Txid_d txid_d);

void append_item(Integer buffer[4][16], PreimageBuilderState state, BitcoinPublicKey_d publickey_d);

void append_item(Integer buffer[4][16], PreimageBuilderState state, Balance_d balance_d);

void append_item(Integer buffer[4][16], PreimageBuilderState state, Integer[8] hash_d);

void fill_buffer(Integer buffer[4][16], PreimageBuilderState state, Integer lengthChunk);




void append_item(Integer buffer[5][16], PreimageBuilderState state, Txid_d txid_d);

void append_item(Integer buffer[5][16], PreimageBuilderState state, BitcoinPublicKey_d publickey_d);

void append_item(Integer buffer[5][16], PreimageBuilderState state, Balance_d balance_d);

void append_item(Integer buffer[5][16], PreimageBuilderState state, Integer[8] hash_d);

void fill_buffer(Integer buffer[5][16], PreimageBuilderState state, Integer lengthChunk);




int append_item(Integer buffer[16], PreimageBuilderState state, Integer[5] input, int startingIndex);

int append_item(Integer buffer[16], PreimageBuilderState state, Integer[8] input, int startingIndex);

int append_item(Integer buffer[16], PreimageBuilderState state, Integer input, int startingIndex, int length);

int fill_buffer(Integer buffer[16], PreimageBuilderState state, Integer lengthChunk);