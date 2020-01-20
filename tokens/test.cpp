#include "test.h"
#include<iostream>
using namespace std;

void test_ecdsa_e2e(EcdsaPartialSig_l psl, uint32_t digest[8]) {

  // also does nothing
  cout << "here we are doing something wooo" << endl;

  // format partial signature
  /*
  EcdsaPartialSig_l psl;
  fillEcdsaPartialSig_l(&psl, r, k_inv);
  EcdsaPartialSig_d psd = distribute_EcdsaPartialSig(psl);

  // compute and parse result
  string actual = ecdsa_sign_hashed(e, psd).reveal_unsigned(PUBLIC);
  string myfull = r + actual;
  actual = change_base(actual, 10, 16);
  while (actual.length() < 64) {
    actual = '0' + actual;
  }
  */
}
