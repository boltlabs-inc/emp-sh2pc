#pragma once
#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;

typedef struct Constants Constants;
struct Constants {
    Integer ipad;
    Integer xeight; //0x80000000;
    Integer hmacinnerhashlength;
    Integer opad;
    Integer hmacouterhashlength;
    Integer hmackeycommitmentpreimagelength;
    Integer fullF;
    Integer doubleshapreimagelength;
    Integer revlockcommitmentpreimagelength;
    Integer maskcommitmentpreimagelength;

    //Integer k[64];
    //Integer H[8];
    Integer xsixthreedot;
    Integer eighteight;
    Integer xtwentyone;
    Integer sixsevenzero;
    Integer twohundred;
    Integer xcfzerofive;
    Integer btwosevenfive;
    Integer customerdelayerscriptpreimagelength;
    Integer sixeightac;
    Integer xtwentytwodot;
    Integer sixteen;
    Integer xzerozerofourteen;
    Integer threesevensixa;
    Integer xfourtyone;
    Integer xeightthirdbyte;
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
    Integer escrowpreimagelength; // 228*8 = 1824 bits
    Integer xseventwosixdot;
    Integer xzerozerotwentyone;
    Integer fiftytwo;
    Integer xaedot;
    Integer xzerofivedot;
    Integer acsixeightzerozero;
    Integer ff;
    Integer ffffffzerozero;
    Integer one;
    Integer xeightfourthbyte;
    Integer merchpreimagelength; // 271*8 = 2168 bits
    Integer xzerozeroff;
    Integer ffzerozero;
    Integer thirtytwo;
    
    Integer zero;
    Integer dustlimit;
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
