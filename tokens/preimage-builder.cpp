#include "emp-sh2pc/emp-sh2pc.h"
#include "preimage-builder.h"


void append_item(Integer buffer[2][16], PreimageBuilderState state, RevLock_d rl_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, rl_d.revlock, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}

void append_item(Integer buffer[2][16], PreimageBuilderState state, Balance_d balance_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 8) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, balance.balance, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}

void append_item(Integer buffer[2][16], PreimageBuilderState state, BitcoinPublicKey_d publickey_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;

    Integer first_eight_chunks[8];
    for(int i =0; i<8; i++)
        first_eight_chunks[i] = publickey_d.key[i];

    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, first_eight_chunks, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
    // TODO check if there is space too
    append_item(buffer[indexInBuffer], state, publickey_d.key[9], 0, 1);
}






void append_item(Integer buffer[3][16], PreimageBuilderState state, Balance_d balance_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 8) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, balance.balance, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}

void append_item(Integer buffer[3][16], PreimageBuilderState state, Integer[8] hash_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, hash_d, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}

void append_item(Integer buffer[3][16], PreimageBuilderState state, PublicKeyHash_d merch_publickey_hash_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 40) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, merch_publickey_hash_d.hash, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}

void append_item(Integer buffer[3][16], PreimageBuilderState state, RevLock_d rl_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, rl_d.revlock, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}

void append_item(Integer buffer[3][16], PreimageBuilderState state, BitcoinPublicKey_d publickey_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, publickey_d.key, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
    // TODO deal with the 33rd byte
}







void append_item(Integer buffer[4][16], PreimageBuilderState state, Txid_d txid_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, txid_d.txid, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}

void append_item(Integer buffer[4][16], PreimageBuilderState state, BitcoinPublicKey_d publickey_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, publickey_d.key, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
    // TODO deal with the 33rd byte
}

void append_item(Integer buffer[4][16], PreimageBuilderState state, Balance_d balance_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 8) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, balance_d.balance, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}

void append_item(Integer buffer[4][16], PreimageBuilderState state, Integer[8] hash_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, hash_d, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}






void append_item(Integer buffer[5][16], PreimageBuilderState state, Txid_d txid_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, txid_d.txid, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}

void append_item(Integer buffer[5][16], PreimageBuilderState state, BitcoinPublicKey_d publickey_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, publickey_d.key, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
    // TODO deal with the 33rd byte
}

void append_item(Integer buffer[5][16], PreimageBuilderState state, Balance_d balance_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 8) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, balance_d.balance, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}

void append_item(Integer buffer[5][16], PreimageBuilderState state, Integer[8] hash_d) {
    int indexInBuffer = state.BytesSoFar/64;
    int bytesEncoded = 0;
    while(bytesEncoded < 32) {
        bytesEncoded += append_item(buffer[indexInBuffer], state, hash_d, bytesEncoded);
        indexInBuffer = state.BytesSoFar/64;
    }
}




int append_item(Integer buffer[16], PreimageBuilderState state, Integer input[5], int startingindex) {

    int byteIndexInBuffer = state.BytesSoFar % 64;
    int byteIndexInInput = startingindex;

    int toReturn = computeBytesWeWillEncode(byteIndexInBuffer, byteIndexInInput, 5);

    // number of bytes left in the
    while(byteIndexInBuffer < 64 and byteIndexInInput < 5*4) {
        // see how many bytes we have in the current input chunk
        int chunkIndexInBuffer = byteIndexInBuffer/4;
        int chunkIndexInInput = byteIndexInInput/4;        
        int numberOfBytesLeftInThisInputChunk = 4 - (byteIndexInInput%4); // TODO Handle not full chunks
        int numberOfBytesLeftInThisBufferChunk = 4 - (byteIndexInBuffer%4);

        //(1) perfect amount of space left in the buffer
        if(numberOfBytesLeftInThisBufferChunk == numberOfBytesLeftInThisInputChunk) {
            buffer[chunkIndexInBuffer] = buffer[chunkIndexInBuffer] | input[chunkIndexInInput];
            byteIndexInBuffer += numberOfBytesLeftInThisBufferChunk;
            byteIndexInInput += numberOfBytesLeftInThisInputChunk
        }
        else if (numberOfBytesLeftInThisBufferChunk < numberOfBytesLeftInThisInputChunk) {
            // Theres not enough space in the current chunk
            buffer[chunkIndexInBuffer] = buffer[chunkIndexInBuffer] | input[chunkIndexInInput] >> (32-8*numberOfBytesLeftInThisBufferChunk);
            byteIndexInBuffer += numberOfBytesLeftInThisBufferChunk;
            byteIndexInInput += numberOfBytesLeftInThisBufferChunk
        } else {
            buffer[chunkIndexInBuffer] = buffer[chunkIndexInBuffer] | input[chunkIndexInInput] << (8*(numberOfBytesLeftInThisBufferChunk-numberOfBytesLeftInThisInputChunk));
            byteIndexInBuffer += numberOfBytesLeftInThisInputChunk;
            byteIndexInInput += numberOfBytesLeftInThisInputChunk
        }
    }

    state.BytesSoFar += toReturn;
    return toReturn;
}


int append_item(Integer buffer[16], PreimageBuilderState state, Integer input[8], int startingindex) {

    int byteIndexInBuffer = state.BytesSoFar % 64;
    int byteIndexInInput = startingindex;

    int toReturn = computeBytesWeWillEncode(byteIndexInBuffer, byteIndexInInput, 8);

    // number of bytes left in the
    while(byteIndexInBuffer < 64 and byteIndexInInput < 8*4) {
        // see how many bytes we have in the current input chunk
        int chunkIndexInBuffer = byteIndexInBuffer/4;
        int chunkIndexInInput = byteIndexInInput/4;        
        int numberOfBytesLeftInThisInputChunk = 4 - (byteIndexInInput%4); // TODO Handle not full chunks
        int numberOfBytesLeftInThisBufferChunk = 4 - (byteIndexInBuffer%4);

        //(1) perfect amount of space left in the buffer
        if(numberOfBytesLeftInThisBufferChunk == numberOfBytesLeftInThisInputChunk) {
            buffer[chunkIndexInBuffer] = buffer[chunkIndexInBuffer] | input[chunkIndexInInput];
            byteIndexInBuffer += numberOfBytesLeftInThisBufferChunk;
            byteIndexInInput += numberOfBytesLeftInThisInputChunk
        }
        else if (numberOfBytesLeftInThisBufferChunk < numberOfBytesLeftInThisInputChunk) {
            // Theres not enough space in the current chunk
            buffer[chunkIndexInBuffer] = buffer[chunkIndexInBuffer] | input[chunkIndexInInput] >> (32-8*numberOfBytesLeftInThisBufferChunk);
            byteIndexInBuffer += numberOfBytesLeftInThisBufferChunk;
            byteIndexInInput += numberOfBytesLeftInThisBufferChunk
        } else {
            buffer[chunkIndexInBuffer] = buffer[chunkIndexInBuffer] | input[chunkIndexInInput] << (8*(numberOfBytesLeftInThisBufferChunk-numberOfBytesLeftInThisInputChunk));
            byteIndexInBuffer += numberOfBytesLeftInThisInputChunk;
            byteIndexInInput += numberOfBytesLeftInThisInputChunk
        }
    }

    state.BytesSoFar += toReturn;
    return toReturn;
}

int append_item(Integer buffer[16], PreimageBuilderState state, Integer input, int startingIndex, int length) {

    int byteIndexInBuffer = state.BytesSoFar % 64;
    int byteIndexInInput = startingIndex;

    int toReturn = computeBytesWeWillEncode(byteIndexInBuffer, byteIndexInInput, length);

    // number of bytes left in the
    while(byteIndexInBuffer < 64 and byteIndexInInput < 8*4) {
        // see how many bytes we have in the current input chunk
        int chunkIndexInBuffer = byteIndexInBuffer/4;
        int chunkIndexInInput = byteIndexInInput/4;        
        int numberOfBytesLeftInThisInputChunk = 4 - (byteIndexInInput%4); // TODO Handle not full chunks
        int numberOfBytesLeftInThisBufferChunk = 4 - (byteIndexInBuffer%4);

        //(1) perfect amount of space left in the buffer
        if(numberOfBytesLeftInThisBufferChunk == numberOfBytesLeftInThisInputChunk) {
            buffer[chunkIndexInBuffer] = buffer[chunkIndexInBuffer] | input[chunkIndexInInput];
            byteIndexInBuffer += numberOfBytesLeftInThisBufferChunk;
            byteIndexInInput += numberOfBytesLeftInThisInputChunk
        }
        else if (numberOfBytesLeftInThisBufferChunk < numberOfBytesLeftInThisInputChunk) {
            // Theres not enough space in the current chunk
            buffer[chunkIndexInBuffer] = buffer[chunkIndexInBuffer] | input[chunkIndexInInput] >> (32-8*numberOfBytesLeftInThisBufferChunk);
            byteIndexInBuffer += numberOfBytesLeftInThisBufferChunk;
            byteIndexInInput += numberOfBytesLeftInThisBufferChunk
        } else {
            buffer[chunkIndexInBuffer] = buffer[chunkIndexInBuffer] | input[chunkIndexInInput] << (8*(numberOfBytesLeftInThisBufferChunk-numberOfBytesLeftInThisInputChunk));
            byteIndexInBuffer += numberOfBytesLeftInThisInputChunk;
            byteIndexInInput += numberOfBytesLeftInThisInputChunk
        }
    }

    state.BytesSoFar += toReturn;
    return toReturn;
}

int computeBytesWeWillEncode(int byteIndexInBuffer, int byteIndexInInput, int length) {
    if (64-byteIndexInBuffer < 4*length-byteIndexInInput) {
        return 64-byteIndexInBuffer;
    } else {
        return 4*length-byteIndexInInput;
    }
}