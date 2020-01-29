#ifndef TOKENS_INCLUDE_H_
#define TOKENS_INCLUDE_H_

#ifdef __cplusplus
extern "C" {
#include <stdint.h>
#endif

/*
 * Types of allowed IO connections
 * - CUSTOM = custom connection handle defined by caller
 * - NETIO = tcp socket on localhost
 * - UNIXNETIO = unix domain socket with a specified file
 * - TORNETIO = onion-routing based connection
 */
enum ConnType { CUSTOM = 0, NETIO, UNIXNETIO, TORNETIO };

/* IO Channel Callback interface - allows caller to handle
 * how connection is made between customer and merchant
 */
typedef void* (*IOCallback)(ConnType c, int party);

/* Returns a pointer to a NetIO ptr */
void* get_netio_ptr(char *address, int port, int party);

/* Returns a pointer to a UnixNetIO ptr */
void* get_unixnetio_ptr(char *socket_path, int party);

/*
 * describes an API for calling MPC functions 
 * 
 * to be integrated into Rust implementation
 *
 * This describes the basic high-level inputs we expect from the protocol.
 * There is some additional precomputation that will happen in the clear,
 * plus mangling of pretty Rust/C++ types to match the format used by
 * the MPC frameworks
 *
 * TYPISSUE - There are some weird types here, as well. Everything has a type,
 * but some of them are clearly incorrect 
 * (e.g.a public key will not fit into a normal 32-bit integer). 
 * but I don't know what representation they -will- take.
 * I've marked such parameters with TYPISSUE
 *
 * Uses char * instead of int for compatibility with Rust.
 *
 * Comments are sort of in doxygen style.
 */

/**** LOCAL TYPES ****/
/* These types are "local" e.g. traditional C variables held completely in memory.
 * You can tell because they all end in _l
 * They have distributed counterparts defined in tokens-misc.h
 */

/* HMAC Key structure.
 * HMAC Keys are the length of the block-size of the underlying hash functions
 * SHA256 has a block size of 512 bits, so we need 16 integers to represent the whole thing
 */
struct HMACKey_l {
  uint32_t key[16]; //TODO uint8_t[64] seems better
};

/* A Commitment to an HMAC Key
 * We are using hash based commitments, so this is really just the output of a SHA256 invocation
 */

struct HMACKeyCommitment_l {
  uint32_t commitment[8];
};

/* random mask value */
struct Mask_l {
  uint32_t mask[8];
};

/* commitment to a random mask value (uses HMAC) */
struct MaskCommitment_l {
  uint32_t commitment[8];
};


/* This is a pay token
 * Is is an HMAC computed on the state 
 * The output of HMAC is the underlying block size.  In this case 256 bits
 */
struct PayToken_l {
  uint32_t paytoken[8];
};

/* This is the second part of an ecdsa signature
 * In this case 256 bits
 */
struct EcdsaSig_l {
  uint32_t sig[8];
};

/* ECDSA partial signature
* This is a partial signature. It is based on a raondomly chosen k, message x, public key G, and public modulus q. Let (rx, ry) = kG.
* \param r     : r = rx*x mod q. Represented as a decimal string. (256 bits)
* \param k_inv : k_inv = k^-1. Represented as a decimal string. (256 bits)
*
* The parameter sizes are overly generous since we're storing them as decimal.
*/
struct EcdsaPartialSig_l {
  char r[256]; 
  char k_inv[256];
};

/* This is a nonce.  Its used to prevent double spends
 * RIGHT NOW THIS THING IS 96 BITS.  WE MAY WANT TO INCREASE ITS LENGTH IN THE FUTURE!!!
 */
struct Nonce_l {
  uint32_t nonce[4];
};
/* Revocation lock - TYPISSUE: not sure what type this is yet.
 * Tentatively sized to use a hash (SHA256-based) commitment scheme.
 * \param rl 	: a revocation lock.
 */
struct RevLock_l {
  uint32_t revlock[8];
};

struct RevLockCommitment_l {
  uint32_t commitment[8];
};

/* bitcoin-flavored transaction id
 */
struct Txid_l {
  uint32_t txid[8];
};

struct BitcoinPublicKey_l {
  uint32_t key[9]; // last byte padded with zeros.
};

struct PublicKeyHash_l {
  uint32_t hash[5];
};

struct Balance_l {
  uint32_t balance[2];
};

struct CommitmentRandomness_l {
  uint32_t randomness[4];
};

/* state type
 *
 * \param nonce         : unique identifier for the transaction?
 * \param rl 			: revocation lock for current state
 * \param balance_cust  : customer balance 
 * \param balance_merch : merchant balance
 * \param txid_merch    : transaction ID for merchant close transaction (bits, formatted as they appear in the 'source' field of a transaction that spends it) 
 * \param txid_escrow   : transaction ID for escrow transaction (ditto on format)
 */
struct State_l {
  struct Nonce_l nonce;
  struct RevLock_l rl;
  struct Balance_l balance_cust;
  struct Balance_l balance_merch;
  struct Txid_l txid_merch;
  struct Txid_l txid_escrow;
  struct Txid_l HashPrevOuts_merch;
  struct Txid_l HashPrevOuts_escrow;
};

/* customer's token generation function
 *
 * runs MPC to compute masked tokens (close- and pay-).
 * blocks until computation is finished.
 *
 * Pads close_tx_escrow and close_tx_merch to exactly 1024 bits according to the SHA256 spec.
 *
 * option: port could be fixed in advance (not passed in here)
 * 
 * \param[in] pkM         : (shared) merchant public key TYPISSUE: what is this?
 * \param[in] amount      : (shared) transaction amount 
 * \param[in] rl_com      : (shared) A commitment to the previous state revocation lock
 * \param[in] port        : (shared) communication port
 * \param[in] ip_addr     : (shared) customer's IP address
 * \param[in] paymask_com : (shared) A commitment to the pay mask (using HMAC)
 * \param[in] com_to_key  : (shared) A commitment to an HMAC key
 *
 * \param[in] w_new     : (private) new state object
 * \param[in] w_old     : (private) previous state object
 * \param[in] t_new     : (private) commitment randomness (TYPISSUE - size?)
 * \param[in] pt_old    : (private) previous pay token
 * \param[in] close_tx_escrow   : (private) bits of new close transaction (spends from escrow). no more than 1024 bits.
 * \param[in] close_tx_merch    : (private) bits of new close transaction (spends from merchant close transaction). No more than 1024 bits.
 * 
 * \param[out] ct_masked    : masked close token (ECDSA signature) (TYPISSUE - representation (serialized)?)
 * \param[out] pt_masked    : masked pay token (tentative: ECDSA signature) (TYPISSUE - representation (serialized)?)
 *
 */
void build_masked_tokens_cust(
  IOCallback io_callback,
  ConnType conn_type,
  struct Balance_l epsilon_l,
  struct RevLockCommitment_l rlc_l, // TYPISSUE: this doesn't match the docs. should be a commitment
  struct CommitmentRandomness_l revlock_commitment_randomness_l,

  struct MaskCommitment_l paymask_com,
  struct HMACKeyCommitment_l key_com,
  struct BitcoinPublicKey_l merch_escrow_pub_key_l,
  struct BitcoinPublicKey_l merch_dispute_key_l,
  struct PublicKeyHash_l merch_publickey_hash,
  struct BitcoinPublicKey_l merch_payout_pub_key_l,
  struct Nonce_l nonce_l,

  struct State_l w_new,
  struct State_l w_old,
  struct PayToken_l pt_old,
  struct BitcoinPublicKey_l cust_escrow_pub_key_l,
  struct BitcoinPublicKey_l cust_payout_pub_key_l,

  struct PayToken_l* pt_return,
  struct EcdsaSig_l* ct_escrow,
  struct EcdsaSig_l* ct_merch
);


/* merchant's close-token computation function 
 *
 * Pre-computes some parameters, then runs MPC to compute masked tokens (close- and pay-)
 * blocks until computation is finished.
 *
 * Generates a partial ECDSA signature:
 *   1. Sample: k <- Z_q, k
 *   2. Compute random curve point: (r_x, r_y) = k * G
 *   3. Compute secret curve point: spt = (r_x * skM) mod q
 *   4. Compute inverse: k_inv = k^(-1)
 * Then calls MPC with shared inputs, plus k_inv, spt.
 *
 * option: port could be fixed in advance (not passed in here)
 *
 * \param[in] pkM         : (shared) merchant public key TYPISSUE: what is this?
 * \param[in] amount      : (shared) transaction amount 
 * \param[in] rl_com      : (shared) A commitment to the previous state revocation lock
 * \param[in] port        : (shared) communication port
 * \param[in] ip_addr     : (shared) customer's IP address
 * \param[in] paymask_com : (shared) A commitment to the pay mask (using HMAC)
 * \param[in] com_to_key  : (shared) A commitment to an HMAC key
 *
 * \param[in] hmac_key      : (private) The key used to make HMACs
   \param[in] open_hmac_key : (private) The opening of the commitment to the HMAC key
 * \param[in] close_mask    : (private) A random mask for the close token TYPISSUE: break this into escrow and merch-close separate masks?
 * \param[in] pay_mask      : (private) A random mask for the pay token 
 * \param[in] sig1          : (private) A partial ECDSA signature TODO EXPLAIN THESE
 * \param[in] sig2          : (private) A partial ECDSA signature
 * \param[in] sig3          : (private) A partial ECDSA signature TODO is this for the pay token? remove if so.
 *
 * Merchant does not receive output.
 *
 */
void build_masked_tokens_merch(
  IOCallback io_callback,
  ConnType conn_type,
  struct Balance_l epsilon_l,
  struct RevLockCommitment_l rlc_l, // TYPISSUE: this doesn't match the docs. should be a commitment
  struct MaskCommitment_l paymask_com,
  struct HMACKeyCommitment_l key_com,
  struct BitcoinPublicKey_l merch_escrow_pub_key_l,
  struct BitcoinPublicKey_l merch_dispute_key_l,
  struct PublicKeyHash_l merch_publickey_hash, // TODO: what is this?
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
);

#ifdef __cplusplus
}
#endif
#endif // TOKENS_INCLUDE_H_
