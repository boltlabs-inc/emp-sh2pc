#pragma once
#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;

typedef struct Constants Constants;
struct Constants {
    Integer ipad;
    Integer xeight; //0x80000000;
    Integer threeazero; //0x000003a0;
    Integer opad;
    Integer threehundred; //0x00000300;
    Integer sixforty;
    Integer fullF;
    Integer twofivesix;
    Integer threeeightfour;

    //Integer k[64];
    //Integer H[8];
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
    
    Integer zero;
};

typedef struct Q Q;
struct Q {
    Integer q;
    Integer q2;
};

Q distribute_Q(const int party);
Constants distribute_Constants(const int party);
Bit constants_not_equal(const Constants& lhs, const Constants& rhs);
Bit q_not_equal(const Q& lhs, const Q& rhs);
