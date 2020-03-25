#include "constants.h"

Constants distribute_Constants(const int party) {
    return Constants {
      .ipad =Integer(32, 909522486, party),
      .xeight =Integer(32, -2147483648, party), //0x80000000;
      .threeazero =Integer(32, 2048, party), //0x000003a0;
      .opad =Integer(32, 1549556828, party),
      .threehundred =Integer(32, 768, party), //0x00000300;
      .sixforty =Integer(32, 640, party),
      .fullF =Integer(256, 4294967295 /* 0xffffffff */, party),
      .twofivesix =Integer(32, 256, party),
      .threeeightfour =Integer(32, 384, party),
      .xsixthreedot =Integer(32, 1671962624 /*0x63a92000*/, party),
      .eighteight =Integer(32, 136 /*0x00000088*/, party),
      .xtwentyone =Integer(32, 553648128, party),
      .sixsevenzero =Integer(32, 26368/*0x00006700*/, party),
      .twohundred =Integer(32,2 /*0x000002*/, party),
      .xcfzerofive =Integer(32, 3473211392 /*0xcf050000*/, party),
      .btwosevenfive =Integer(32, 45685/*0x0000b275*/, party),
      .eightninesix =Integer(32, 896, party),
      .sixeightac =Integer(32, 26796/*0x000068ac*/, party),
      .xtwentytwodot =Integer(32, 570433536 /*0x22002000*/, party),
      .sixteen =Integer(32, 22 /*0x00000016*/, party),
      .xzerozerofourteen =Integer(32, 1310720 /*0x00140000*/, party),
      .threesevensixa =Integer(32, 17258/*0x0000376a*/, party),
      .xfourtyone =Integer(32, 1090519040/*0x41000000*/, party),
      .eightthousand =Integer(32,32768 /*0x00008000*/, party),
      .twelvehundred =Integer(32, 1200, party),
      .xzerotwo =Integer(32, 33554432 /*0x02000000*/, party),
      .xthreedot =Integer(32, 1001467945  /*0x3bb13029*/, party),
      .xcdot =Integer(32, 3464175445 /*0xce7b1f55*/, party),
      .xninedot =Integer(32, 2666915655 /*0x9ef5e747*/, party),
      .xfdot =Integer(32, 4239147935 /*0xfcac439f*/, party),
      .xfourteendot =Integer(32,  341156588 /*0x1455a2ec*/, party),
      .xsevendot =Integer(32, 2086603191 /*0x7c5f09b7*/, party),
      .xtwentytwoninedot =Integer(32,  579893598 /*0x2290795e*/, party),
      .xsevenzerosixdot  =Integer(32, 1885753412  /*0x70665044*/, party),
      .xfoursevenfivedot =Integer(32, 1196564736/*0x47522100*/, party),
      .fivetwoae =Integer(32, 21166/*0x000052ae*/, party),
      .fullFthirtytwo =Integer(32, 4294967295 /*0xffffffff*/, party),
      .xzeroone =Integer(32, 16777216 /*0x01000000*/, party),
      .oneeighttwofour =Integer(32, 1824, party), // 228*8 = 1824 bits
      .xseventwosixdot =Integer(32, 1919111713 /* 0x72635221*/, party),
      .xzerozerotwentyone =Integer(32, 2162688 /*0x00210000*/, party),
      .fiftytwo =Integer(32, 82/*0x00000052*/, party),
      .xaedot =Integer(32, 2925986511 /* 0xae6702cf */, party),
      .xzerofivedot =Integer(32,   95581473 /* 0x05b27521 */, party),
      .acsixeightzerozero =Integer(32, 11298816/* 0x00ac6800 */, party),
      .ff =Integer(32, 255 /* 0x000000ff */ , party),
      .ffffffzerozero =Integer(32, 4294967040 /*0xffffff00*/, party),
      .one =Integer(32, 1 /*0x00000001*/, party),
      .eighty =Integer(32, 128 /*0x00000080*/, party),
      .twoonesixeight =Integer(32, 2168, party), // 271*8 = 2168 bits

      .xzerozeroff =Integer(32, 16711680 /* 00ff0000 */, party),
      .ffzerozero =Integer(32, 65280 /* 0000ff00 */, party),
      .thirtytwo =Integer(256, 32, party),
      .zero =Integer(32, 0, party)
  };
}

Bit constants_not_equal(const Constants& lhs, const Constants& rhs) {
	Bit error_signal(false);

	error_signal = error_signal | !lhs.ipad.equal(rhs.ipad);
    error_signal = error_signal | !lhs.xeight.equal(rhs.xeight);
    error_signal = error_signal | !lhs.threeazero.equal(rhs.threeazero);
    error_signal = error_signal | !lhs.opad.equal(rhs.opad);
    error_signal = error_signal | !lhs.threehundred.equal(rhs.threehundred);
    error_signal = error_signal | !lhs.sixforty.equal(rhs.sixforty);
    error_signal = error_signal | !lhs.fullF.equal(rhs.fullF);
    error_signal = error_signal | !lhs.twofivesix.equal(rhs.twofivesix);
    error_signal = error_signal | !lhs.threeeightfour.equal(rhs.threeeightfour);

    error_signal = error_signal | !lhs.xsixthreedot.equal(rhs.xsixthreedot);
    error_signal = error_signal | !lhs.eighteight.equal(rhs.eighteight);
    error_signal = error_signal | !lhs.xtwentyone.equal(rhs.xtwentyone);
    error_signal = error_signal | !lhs.sixsevenzero.equal(rhs.sixsevenzero);
    error_signal = error_signal | !lhs.twohundred.equal(rhs.twohundred);
    error_signal = error_signal | !lhs.xcfzerofive.equal(rhs.xcfzerofive);
    error_signal = error_signal | !lhs.btwosevenfive.equal(rhs.btwosevenfive);
    error_signal = error_signal | !lhs.eightninesix.equal(rhs.eightninesix);
    error_signal = error_signal | !lhs.sixeightac.equal(rhs.sixeightac);
    error_signal = error_signal | !lhs.xtwentytwodot.equal(rhs.xtwentytwodot);
    error_signal = error_signal | !lhs.sixteen.equal(rhs.sixteen);
    error_signal = error_signal | !lhs.xzerozerofourteen.equal(rhs.xzerozerofourteen);
    error_signal = error_signal | !lhs.threesevensixa.equal(rhs.threesevensixa);
    error_signal = error_signal | !lhs.xfourtyone.equal(rhs.xfourtyone);
    error_signal = error_signal | !lhs.eightthousand.equal(rhs.eightthousand);
    error_signal = error_signal | !lhs.twelvehundred.equal(rhs.twelvehundred);
    error_signal = error_signal | !lhs.xzerotwo.equal(rhs.xzerotwo);
    error_signal = error_signal | !lhs.xthreedot.equal(rhs.xthreedot);
    error_signal = error_signal | !lhs.xcdot.equal(rhs.xcdot);
    error_signal = error_signal | !lhs.xninedot.equal(rhs.xninedot);
    error_signal = error_signal | !lhs.xfdot.equal(rhs.xfdot);
    error_signal = error_signal | !lhs.xfourteendot.equal(rhs.xfourteendot);
    error_signal = error_signal | !lhs.xsevendot.equal(rhs.xsevendot);
    error_signal = error_signal | !lhs.xtwentytwoninedot.equal(rhs.xtwentytwoninedot);
    error_signal = error_signal | !lhs.xsevenzerosixdot.equal(rhs.xsevenzerosixdot);
    error_signal = error_signal | !lhs.xfoursevenfivedot.equal(rhs.xfoursevenfivedot);
    error_signal = error_signal | !lhs.fivetwoae.equal(rhs.fivetwoae);
    error_signal = error_signal | !lhs.fullFthirtytwo.equal(rhs.fullFthirtytwo);
    error_signal = error_signal | !lhs.xzeroone.equal(rhs.xzeroone);
    error_signal = error_signal | !lhs.oneeighttwofour.equal(rhs.oneeighttwofour);
    error_signal = error_signal | !lhs.xseventwosixdot.equal(rhs.xseventwosixdot);
    error_signal = error_signal | !lhs.xzerozerotwentyone.equal(rhs.xzerozerotwentyone);
    error_signal = error_signal | !lhs.fiftytwo.equal(rhs.fiftytwo);
    error_signal = error_signal | !lhs.xaedot.equal(rhs.xaedot);
    error_signal = error_signal | !lhs.xzerofivedot.equal(rhs.xzerofivedot);
    error_signal = error_signal | !lhs.acsixeightzerozero.equal(rhs.acsixeightzerozero);
    error_signal = error_signal | !lhs.ff.equal(rhs.ff);
    error_signal = error_signal | !lhs.ffffffzerozero.equal(rhs.ffffffzerozero);
    error_signal = error_signal | !lhs.one.equal(rhs.one);
    error_signal = error_signal | !lhs.eighty.equal(rhs.eighty);
    error_signal = error_signal | !lhs.twoonesixeight.equal(rhs.twoonesixeight);

    error_signal = error_signal | !lhs.xzerozeroff.equal(rhs.xzerozeroff);
    error_signal = error_signal | !lhs.ffzerozero.equal(rhs.ffzerozero);
    error_signal = error_signal | !lhs.thirtytwo.equal(rhs.thirtytwo);

    error_signal = error_signal | !lhs.zero.equal(rhs.zero);
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