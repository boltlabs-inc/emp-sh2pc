#include "constants.h"

Constants distribute_Constants(const int party) {
    return Constants {
      // HMAC Constants
      .ipad =Integer(32, 909522486, party),
      .opad =Integer(32, 1549556828, party),

      // SHA256 Constants
      .xeightfirstbyte =Integer(32, -2147483648, party), /*0x80000000*/
      .xeightsecondbyte =Integer(32, 8388608, party),    /*0x00800000*/
      .xeightthirdbyte =Integer(32,32768 , party),       /*0x00008000*/
      .xeightfourthbyte =Integer(32, 128 , party),       /*0x00000080*/

      // Length of stuff Constants
      .hmacinnerhashlength =Integer(32, 2240, party),
      .hmacouterhashlength =Integer(32, 768, party),
      .hmackeycommitmentpreimagelength =Integer(32, 640, party),
      .doubleshapreimagelength =Integer(32, 256, party),

      .revlockcommitmentpreimagelength =Integer(32, 384, party),
      .maskcommitmentpreimagelength =Integer(32, 384, party),

      .customerdelayerscriptpreimagelength =Integer(32, 896, party),
      .escrowtransactionpreimagelength =Integer(32, 1824, party),
      .merchtransactionpreimagelength =Integer(32, 2168, party),
      .hashoutputspreimagelength =Integer(32, 1448, party),


      // Constants for transactions
      .xsixthreedot =Integer(32, 1671962624 , party),       /*0x63a92000*/
      .eighteight =Integer(32, 136 , party),                /*0x00000088*/
      .xtwentyone =Integer(32, 553648128, party),           /*0x21000000*/
      .sixsevenzero =Integer(32, 26368, party),             /*0x00006700*/
      .btwosevenfive =Integer(32, 45685, party),            /*0x0000b275*/
      .sixeightac =Integer(32, 26796, party),               /*0x000068ac*/
      .xtwentytwodot =Integer(32, 570433536 , party),       /*0x22002000*/
      .sixteen =Integer(32, 22 , party),                    /*0x00000016*/
      .xzerozerofourteen =Integer(32, 1310720 , party),     /*0x00140000*/
      .threesevensixa =Integer(32, 17258, party),           /*0x0000376a*/
      .xfourtyone =Integer(32, 1090519040, party),          /*0x41000000*/
      .xzerotwo =Integer(32, 33554432 , party),             /*0x02000000*/
      .xthreedot =Integer(32, 1001467945  , party),         /*0x3bb13029*/
      .xcdot =Integer(32, 3464175445 , party),              /*0xce7b1f55*/
      .xninedot =Integer(32, 2666915655 , party),           /*0x9ef5e747*/
      .xfdot =Integer(32, 4239147935 , party),              /*0xfcac439f*/
      .xfourteendot =Integer(32,  341156588 , party),       /*0x1455a2ec*/
      .xsevendot =Integer(32, 2086603191 , party),          /*0x7c5f09b7*/
      .xtwentytwoninedot =Integer(32,  579893598 , party),  /*0x2290795e*/
      .xsevenzerosixdot  =Integer(32, 1885753412  , party), /*0x70665044*/
      .xfoursevenfivedot =Integer(32, 1196564736, party),   /*0x47522100*/
      .fivetwoae =Integer(32, 21166, party),                /*0x000052ae*/
      .xzeroone =Integer(32, 16777216 , party),             /*0x01000000*/
      .xseventwosixdot =Integer(32, 1919111713 , party),    /*0x72635221*/
      .xzerozerotwentyone =Integer(32, 2162688 , party),    /*0x00210000*/
      .fiftytwo =Integer(32, 82, party),                    /*0x00000052*/
//      .xaedot =Integer(32, 2925985792, party),              /*0xae670000*/
      .xaedot =Integer(32, 2925986304, party),              /*0xae670200*/
      .xzerofivedot =Integer(32, 11695393, party),          /*0x00b27521*/
      .acsixeightzerozero =Integer(32, 11298816, party),    /*0x00ac6800*/
      .xsixteenzerozero =Integer(32, 5632, party),          /*0x00001600*/
      .xfourteenzerozero =Integer(32, 335544320, party),    /*0x14000000*/

      // Selection masks
      .fullF =Integer(256, 4294967295 /* 0xffffffff */, party),
      .fullFsixtyfour =Integer(64, 4294967295, party),
      .fullFthirtytwo =Integer(32, 4294967295 /*0xffffffff*/, party),
      .xzerozeroff =Integer(32, 16711680 /* 00ff0000 */, party),
      .ff =Integer(32, 255 /* 0x000000ff */ , party),
      .ffffffzerozero =Integer(32, 4294967040 /*0xffffff00*/, party),
      .ffzerozero =Integer(32, 65280 /* 0000ff00 */, party),

      .thirtytwo =Integer(256, 32, party),
      .zero =Integer(32, 0, party),
      .one =Integer(32, 1 /*0x00000001*/, party),
      .lenSelfDelay =Integer(32,2 /*0x00000002*/, party),
  };
}

Bit constants_not_equal(const Constants& lhs, const Constants& rhs) {
	Bit error_signal(false);

  error_signal = error_signal | !lhs.ipad.equal(rhs.ipad);
  error_signal = error_signal | !lhs.opad.equal(rhs.opad);
  error_signal = error_signal | !lhs.xeightfirstbyte.equal(rhs.xeightfirstbyte);
  error_signal = error_signal | !lhs.xeightsecondbyte.equal(rhs.xeightsecondbyte);
  error_signal = error_signal | !lhs.xeightthirdbyte.equal(rhs.xeightthirdbyte);
  error_signal = error_signal | !lhs.xeightfourthbyte.equal(rhs.xeightfourthbyte);
  error_signal = error_signal | !lhs.hmacinnerhashlength.equal(rhs.hmacinnerhashlength);
  error_signal = error_signal | !lhs.hmacouterhashlength.equal(rhs.hmacouterhashlength);
  error_signal = error_signal | !lhs.hmackeycommitmentpreimagelength.equal(rhs.hmackeycommitmentpreimagelength);
  error_signal = error_signal | !lhs.doubleshapreimagelength.equal(rhs.doubleshapreimagelength);
  error_signal = error_signal | !lhs.revlockcommitmentpreimagelength.equal(rhs.revlockcommitmentpreimagelength);
  error_signal = error_signal | !lhs.maskcommitmentpreimagelength.equal(rhs.maskcommitmentpreimagelength);
  error_signal = error_signal | !lhs.customerdelayerscriptpreimagelength.equal(rhs.customerdelayerscriptpreimagelength);
  error_signal = error_signal | !lhs.escrowtransactionpreimagelength.equal(rhs.escrowtransactionpreimagelength);
  error_signal = error_signal | !lhs.merchtransactionpreimagelength.equal(rhs.merchtransactionpreimagelength);
  error_signal = error_signal | !lhs.hashoutputspreimagelength.equal(rhs.hashoutputspreimagelength);
  error_signal = error_signal | !lhs.xsixthreedot.equal(rhs.xsixthreedot);
  error_signal = error_signal | !lhs.eighteight.equal(rhs.eighteight);
  error_signal = error_signal | !lhs.xtwentyone.equal(rhs.xtwentyone);
  error_signal = error_signal | !lhs.sixsevenzero.equal(rhs.sixsevenzero);
  error_signal = error_signal | !lhs.btwosevenfive.equal(rhs.btwosevenfive);
  error_signal = error_signal | !lhs.sixeightac.equal(rhs.sixeightac);
  error_signal = error_signal | !lhs.xtwentytwodot.equal(rhs.xtwentytwodot);
  error_signal = error_signal | !lhs.sixteen.equal(rhs.sixteen);
  error_signal = error_signal | !lhs.xzerozerofourteen.equal(rhs.xzerozerofourteen);
  error_signal = error_signal | !lhs.threesevensixa.equal(rhs.threesevensixa);
  error_signal = error_signal | !lhs.xfourtyone.equal(rhs.xfourtyone);
  error_signal = error_signal | !lhs.xzerotwo.equal(rhs.xzerotwo);
  error_signal = error_signal | !lhs.xthreedot.equal(rhs.xthreedot);
  error_signal = error_signal | !lhs.xcdot.equal(rhs.xcdot);
  error_signal = error_signal | !lhs.xninedot.equal(rhs.xninedot);
  error_signal = error_signal | !lhs.xfdot.equal(rhs.xfdot);
  error_signal = error_signal | !lhs.xfourteendot.equal(rhs.xfourteendot);
  error_signal = error_signal | !lhs.xsevendot.equal(rhs.xsevendot);
  error_signal = error_signal | !lhs.xtwentytwoninedot.equal(rhs.xtwentytwoninedot);
  error_signal = error_signal | !lhs.xsevenzerosixdot .equal(rhs.xsevenzerosixdot );
  error_signal = error_signal | !lhs.xfoursevenfivedot.equal(rhs.xfoursevenfivedot);
  error_signal = error_signal | !lhs.fivetwoae.equal(rhs.fivetwoae);
  error_signal = error_signal | !lhs.xzeroone.equal(rhs.xzeroone);
  error_signal = error_signal | !lhs.xseventwosixdot.equal(rhs.xseventwosixdot);
  error_signal = error_signal | !lhs.xzerozerotwentyone.equal(rhs.xzerozerotwentyone);
  error_signal = error_signal | !lhs.fiftytwo.equal(rhs.fiftytwo);
  error_signal = error_signal | !lhs.xaedot.equal(rhs.xaedot);
  error_signal = error_signal | !lhs.xzerofivedot.equal(rhs.xzerofivedot);
  error_signal = error_signal | !lhs.acsixeightzerozero.equal(rhs.acsixeightzerozero);
  error_signal = error_signal | !lhs.xsixteenzerozero.equal(rhs.xsixteenzerozero);
  error_signal = error_signal | !lhs.xfourteenzerozero.equal(rhs.xfourteenzerozero);
  error_signal = error_signal | !lhs.fullF.equal(rhs.fullF);
  error_signal = error_signal | !lhs.fullFsixtyfour.equal(rhs.fullFsixtyfour);
  error_signal = error_signal | !lhs.fullFthirtytwo.equal(rhs.fullFthirtytwo);
  error_signal = error_signal | !lhs.xzerozeroff.equal(rhs.xzerozeroff);
  error_signal = error_signal | !lhs.ff.equal(rhs.ff);
  error_signal = error_signal | !lhs.ffffffzerozero.equal(rhs.ffffffzerozero);
  error_signal = error_signal | !lhs.ffzerozero.equal(rhs.ffzerozero);
  error_signal = error_signal | !lhs.thirtytwo.equal(rhs.thirtytwo);
  error_signal = error_signal | !lhs.zero.equal(rhs.zero);
  error_signal = error_signal | !lhs.one.equal(rhs.one);
  error_signal = error_signal | !lhs.lenSelfDelay.equal(rhs.lenSelfDelay);
	return error_signal;
}

Bit q_not_equal(const Q& lhs, const Q& rhs) {
	Bit error_signal(false);

    error_signal = error_signal | !lhs.q2.equal(rhs.q2);
    error_signal = error_signal | !lhs.q.equal(rhs.q);

	return error_signal;
}

Q distribute_Q(const int party) {
  string q2str = "57896044618658097711785492504343953926418782139537452191302581570759080747169";
  Integer q2(516, q2str, party);
  string qstr = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
  Integer q(258, qstr, party);
  return Q{
      .q = q,
      .q2 = q2
  };
}