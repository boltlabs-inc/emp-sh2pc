#pragma once
#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;

typedef struct Constants Constants;
struct Constants {
    Integer ipad;
    Integer opad;

    Integer xeightfirstbyte;
    Integer xeightsecondbyte;
    Integer xeightthirdbyte;
    Integer xeightfourthbyte;

    Integer hmacinnerhashlength;
    Integer hmacouterhashlength;
    Integer hmackeycommitmentpreimagelength;
    Integer doubleshapreimagelength;
    Integer revlockcommitmentpreimagelength;
    Integer maskcommitmentpreimagelength;
    Integer customerdelayerscriptpreimagelength;
    Integer escrowtransactionpreimagelength;
    Integer merchtransactionpreimagelength;
    Integer hashoutputspreimagelength;

    Integer xsixthreedot;
    Integer eighteight;
    Integer xtwentyone;
    Integer sixsevenzero;
    Integer btwosevenfive;
    Integer sixeightac;
    Integer xtwentytwodot;
    Integer sixteen;
    Integer xzerozerofourteen;
    Integer threesevensixa;
    Integer xfourtyone;
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
    Integer xzeroone;
    Integer xseventwosixdot;
    Integer xzerozerotwentyone;
    Integer fiftytwo;
    Integer xaedot;
    Integer xzerofivedot;
    Integer acsixeightzerozero;
    Integer xsixteenzerozero;
    Integer xfourteenzerozero;

    Integer fullF;
    Integer fullFsixtyfour;
    Integer fullFthirtytwo;
    Integer xzerozeroff;
    Integer ff;
    Integer ffffffzerozero;
    Integer ffzerozero;

    Integer thirtytwo;
    Integer zero;
    Integer one;
    Integer lenSelfDelay;
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
