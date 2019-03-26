#pragma once

#include "cclient/api/core/core_api.h"
#include "cclient/api/extended/extended_api.h"
#include "utils/time.h"

static char const* amazon_ca1_pem =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\r\n"
    "ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\r\n"
    "b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\r\n"
    "MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\r\n"
    "b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\r\n"
    "ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\r\n"
    "9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\r\n"
    "IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\r\n"
    "VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\r\n"
    "93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\r\n"
    "jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\r\n"
    "AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\r\n"
    "A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\r\n"
    "U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\r\n"
    "N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\r\n"
    "o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\r\n"
    "5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\r\n"
    "rqXRfboQnoZsG4q5WTP468SQvvG5\r\n"
    "-----END CERTIFICATE-----\r\n";

static tryte_t const *const HASH_1 = (tryte_t*)"RVORZ9SIIP9RCYMREUIXXVPQIPHVCNPQ9HZWYKFWYWZRE9JQKG9REPKIASHUUECPSQO9JT9XNMVKWYGVA";
static tryte_t const *const HASH_2 = (tryte_t*)"99999999IP9RCYMREUIXXVPQIPHVCNPQ9HZWYKFWYWZRE9JQKG9REPKIASHUUECPSQO9JT9XNMVKWYGVA";
static tryte_t const *const HASH_3 = (tryte_t*)"OAATQS9VQLSXCLDJVJJVYUGONXAXOFMJOZNSYWRZSWECMXAQQURHQBJNLD9IOFEPGZEPEMPXCIVRX9999";

static tryte_t const *const TRYRES_2673 = (tryte_t*) "BYSWEAUTWXHXZ9YBZISEK9LUHWGMHXCGEVNZHRLUWQFCUSDXZHOFHWHL9MQPVJXXZLIXPX"
  "PXF9KYEREFSKCPKYIIKPZVLHUTDFQKKVVBBN9ATTLPCNPJDWDEVIYYLGPZGCWXOBDXMLJC9V"
  "O9QXTTBLAXTTBFUAROYEGQIVB9MJWJKXJMCUPTWAUGFZBTZCSJVRBGMYXTVBDDS9MYUJCPZ9"
  "YDWWQNIPUAIJXXSNLKUBSCOIJPCLEFPOXFJREXQCUVUMKSDOVQGGHRNILCO9GNCLWFM9APMN"
  "MWYASHXQAYBEXF9QRIHIBHYEJOYHRQJAOKAQ9AJJFQ9WEIWIJOTZATIBOXQLBMIJU9PCGBLV"
  "DDVFP9CFFSXTDUXMEGOOFXWRTLFGV9XXMYWEMGQEEEDBTIJ9OJOXFAPFQXCDAXOUDMLVYRMR"
  "LUDBETOLRJQAEDDLNVIRQJUBZBO9CCFDHIX9MSQCWYAXJVWHCUPTRSXJDESISQPRKZAFKFRU"
  "LCGVRSBLVFOPEYLEE99JD9SEBALQINPDAZHFAB9RNBH9AZWIJOTLBZVIEJIAYGMC9AZGNFWG"
  "RSWAXTYSXVROVNKCOQQIWGPNQZKHUNODGYADPYLZZZUQRTJRTODOUKAOITNOMWNGHJBBA99Q"
  "UMBHRENGBHTH9KHUAOXBVIVDVYYZMSEYSJWIOGGXZVRGN999EEGQMCOYVJQRIRROMPCQBLDY"
  "IGQO9AMORPYFSSUGACOJXGAQSPDY9YWRRPESNXXBDQ9OZOXVIOMLGTSWAMKMTDRSPGJKGBXQ"
  "IVNRJRFRYEZ9VJDLHIKPSKMYC9YEGHFDS9SGVDHRIXBEMLFIINOHVPXIFAZCJKBHVMQZEVWC"
  "OSNWQRDYWVAIBLSCBGESJUIBWZECPUCAYAWMTQKRMCHONIPKJYYTEGZCJYCT9ABRWTJLRQXK"
  "MWY9GWZMHYZNWPXULNZAPVQLPMYQZCYNEPOCGOHBJUZLZDPIXVHLDMQYJUUBEDXXPXFLNRGI"
  "PWBRNQQZJSGSJTTYHIGGFAWJVXWL9THTPWOOHTNQWCNYOYZXALHAZXVMIZE9WMQUDCHDJMIB"
  "WKTYH9AC9AFOT9DPCADCV9ZWUTE9QNOMSZPTZDJLJZCJGHXUNBJFUBJWQUEZDMHXGBPTNSPZ"
  "BR9TGSKVOHMOQSWPGFLSWNESFKSAZY9HHERAXALZCABFYPOVLAHMIHVDBGKUMDXC9WHHTIRY"
  "HZVWNXSVQUWCR9M9RAGMFEZZKZ9XEOQGOSLFQCHHOKLDSA9QCMDGCGMRYJZLBVIFOLBIJPRO"
  "KMHOYTBTJIWUZWJMCTKCJKKTR9LCVYPVJI9AHGI9JOWMIWZAGMLDFJA9WU9QAMEFGABIBEZN"
  "NAL9OXSBFLOEHKDGHWFQSHMPLYFCNXAAZYJLMQDEYRGL9QKCEUEJ9LLVUOINVSZZQHCIKPAG"
  "MT9CAYIIMTTBCPKWTYHOJIIY9GYNPAJNUJ9BKYYXSV9JSPEXYMCFAIKTGNRSQGUNIYZCRT9F"
  "OWENSZQPD9ALUPYYAVICHVYELYFPUYDTWUSWNIYFXPX9MICCCOOZIWRNJIDALWGWRATGLJXN"
  "AYTNIZWQ9YTVDBOFZRKO9CFWRPAQQRXTPACOWCPRLYRYSJARRKSQPR9TCFXDVIXLP9XVL99E"
  "RRDSOHBFJDJQQGGGCZNDQ9NYCTQJWVZIAELCRBJJFDMCNZU9FIZRPGNURTXOCDSQGXTQHKHU"
  "ECGWFUUYS9J9NYQ9U9P9UUP9YMZHWWWCIASCFLCMSKTELZWUGCDE9YOKVOVKTAYPHDF9ZCCQ"
  "AYPJIJNGSHUIHHCOSSOOBUDOKE9CJZGYSSGNCQJVBEFTZFJ9SQUHOASKRRGBSHWKBCBWBTJH"
  "OGQ9WOMQFHWJVEG9NYX9KWBTCAIXNXHEBDIOFO9ALYMFGRICLCKKLG9FOBOX9PDWNQRGHBKH"
  "GKKRLWTBEQMCWQRLHAVYYZDIIPKVQTHYTWQMTOACXZOQCDTJTBAAUWXSGJF9PNQIJ9AJRUMU"
  "VCPWYVYVARKR9RKGOUHHNKNVGGPDDLGKPQNOYHNKAVVKCXWXOQPZNSLATUJT9AUWRMPPSWHS"
  "TTYDFAQDXOCYTZHOYYGAIM9CELMZ9AZPWB9MJXGHOKDNNSZVUDAGXTJJSSZCPZVPZBYNNTUQ"
  "ABSXQWZCHDQSLGK9UOHCFKBIBNETK9999999999999999999999999999999999999999999"
  "99999999999999999999999999999999999999NOXDXXKUDWLOFJLIPQIBRBMGDYCPGDNLQO"
  "LQS99EQYKBIU9VHCJVIPFUYCQDNY9APGEVYLCENJIOBLWNB999999999XKBRHUD99C999999"
  "99NKZKEKWLDKMJCI9N9XQOLWEPAYWSH9999999999999999999999999KDDTGZLIPBNZKMLT"
  "OLOXQVNGLASESDQVPTXALEKRMIOHQLUHD9ELQDBQETS9QFGTYOYWLNTSKKMVJAUXSIROUICD"
  "OXKSYZTDPEDKOQENTJOWJONDEWROCEJIEWFWLUAACVSJFTMCHHXJBJRKAAPUDXXVXFWP9X99"
  "99IROUICDOXKSYZTDPEDKOQENTJOWJONDEWROCEJIEWFWLUAACVSJFTMCHHXJBJRKAAPUDXX"
  "VXFWP9X9999";


static tryte_t const *const SEND_TRYTES_HASH1 = (tryte_t *)"999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999LQZYGHAQLJLENO9IBSFOFIYHIBKOHEWVAEHKYOED9WBER"
  "CCLGGLOJVIZSIUUXGJ9WONIGBXKTVAWUXNHW999999999999999999999999999RRLZ99999"
  "999999999999999999PJEHO9D99A99999999A99999999WP9UOEBRYYUNDHHFIRQUIDAKRLE"
  "LJLBVVXCIL9ENWSAYVJGURYXGRWXDBHHF9RJGZENZWJLNCVCNKURYC999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "RRLZ99999999999999999999999999999999999999999999999999999999999999999999"
  "999999999";

static tryte_t const *const SEND_TRYTES_HASH2 = (tryte_t *)"999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999PNRMSXRHPOFXERGZCCIOHBLXLCSROQXJINLUNDNLTKEMI"
  "ISBYN9GWFOE9M9YOACEYCZA9NGAMMMFUHBAD999999999999999999999999999RRLZ99999"
  "999999999999999999PJEHO9D99999999999A99999999WP9UOEBRYYUNDHHFIRQUIDAKRLE"
  "LJLBVVXCIL9ENWSAYVJGURYXGRWXDBHHF9RJGZENZWJLNCVCNKURYC999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "999999999999999999999999999999999999999999999999999999999999999999999999"
  "RRLZ99999999999999999999999999999999999999999999999999999999999999999999"
  "999999999";

static tryte_t const *const SEND_1K_HASH1 = (tryte_t *)"GKNSMEKQODVBIWRIDZVX9OLBIZDQOKR9DY9UJZSH9FILYHAAJSVLVATHTUIUQVWRYPIJPQDWJUJVL9RBCKZPVPLGEKFOTMGNJJGFCOQLPDJCFZGCMHLHJBKMIFDTTACWGWY9LHPSOTXX9LBHQZAQPLOYYI9NLSNBOBSHBLJXWPWZRUQARJV9QXCBHBPXMUIOSNWONVYLTH9AEJXCEUTJZIASMRETZMAFNGRKJHMOZDUM9XIJZNZAMPNUQKCLNDLRPIT9JQGSQBSJL9DUBFYMWM9ZXNAYR9SKFTBARJZHZPWVSICPAOUPTMHHEGTCVLKSMZYBWWYUFQVZHGAMQMNLPEBPCMVJWCEJLOCQGHXAMWMQRLARGEBUPIOOILEHBJMHGJLSZFOWC9XDFZXDWVITAECVARTCFQMMH9ZEVO9UBQUGESHTQOIJ99HDUQWCKCDGYPSYDLV9THTHD9PCXYJTNXGWNBLCQBRZMUUBXWVSMVDMHDFXXLQVSUNXQIDFRPAOWZDBOQTMZAOFSPCWMAKMBXONF9EVRQAWYOZSLRZQZKCAZRYRDHDAA9ZAUEFETLGELAZXZJP9IUMUZQ9POJEAEJZUUARRDCXUPSIDHHZUYBV9HHBW9DASXPTYBGPSGGMB9WJSJIABPXDUYLLISVJ9WDFKTKWTJPJDNXIQQEJKJJIWHXAMUDNWIUZVOYEHUFYWFCIFCEGT9LOEVXVMDZHMUWOAWOYGFPPJOHCXWO9EWR9BMDYQXNRNIGENIGOEQZVUE9A9XRNCPAWQ9ZBHWFSQYCBSNQ9AXGSZXNTXPUOFFWMPVS9HTQHGJYLPNVARXGH9ZQA9ICAMIGCFHXEIBRBBQXUVBTSA9LT9IIWWUTY9SYHNMLENBAVZLVVCMZC9RUIATPCQJQQOEAAPWGBJMJTZ9POWTKBMRZGNXRDJBSUBJFXCVQLOJRBFCLGZIUBIWPOVIDSGOITGCBZYPFXGUJXRDHCJHNUKLYGGOVSKRV9YJJLUBDDAGNUFTLDOIOGWQXFOYPHSJXVUX9QTPPEUWRTHAYQEZMJQBM9WUELAVZPMCFSFQIXOPLHLADUGFTU9GXGOIGSV9SRYRL9ZMPFEUUJAEPWJE9ZLZ9QELOVVEMNGQJPIW9YRAHXULRYXRF9PQALIMNIWGKTEJTGPCJUWFGMZOPURPZFKNJQCHWEYBXKTLNYPXVYJEDMMJCSTSRYRLBCA9MZHKYDGZPCXVFHJYJVAQFCO9HABUUPZT9FXOEOBCSXTYUABTVSNTEQXDLREZSIVDLJXMZDKIBBEDSYCMBZOCZAJFRUNNPWSA9KUYAE9HDSMXTIMGQRBEKIOEEIWCVZECRUAMBVUAHBAHZMCHFBGVSIAROVXJKFDCMSWDNM9LMMMDHRRZKRHYWMQSJPEOE9TTDYFAWUEITOQRLUQNIDJOWKSKRHISKZPH9Y99DJQRRVPQNHVP9K9DJTTNLBKCFMEZPFWRTABWPZPALTBQNJWQMVPQAHYUOZUCXKXIKMNOTLQROWFHHZOJMSYIEMURGHVCGZII9EWRYPWTOF9ANIINUN9BLUVKGFDYMJLFERDBHIBRMORPRQORXPHISEXOLVGPTYMRGHLXCNJJKMUMTKWAPOYI9LCDYB9LFRDLEZWYMUKQEJXIYTMRVEQEPEPIXSBYXXOTUC9AQUMOXYDXFMCGZHWK9IBAZLMVBLEWYYLMOVBPNWSZJGRPOGHQXRWZPYUDVCLI9ITVTLVTIEOKJKQCRZGIZREDTPSFOLBHPGNT9QKXDXQJRVLNW9BJ9QCJYZZPMITKF9OTUFUEA9VUHNDULQBP99SGSPNOTRNIWTJMUBPY9KRJGEIJREAYCSLILUBEHBFRTDUHWJSXU9LBMMHGKUZNZ9EVHMSSZQSRJCJMKV9BNIEXPXAPJR9MCOSSK9UFPBWPJKJYLHFWIUUWZAESBGDWFMPHPELELWVQG9SLQSHEGFRSEOT9AKNPTPMYSNBSKGUJTVEVOPZCVSIJVTQLIHAONAEGPIWXLANYIARDPOECZPHAOAIJHFUOWMEWQQGGSMIYRQBKFLLMFP9ZSJMW9BKQLSUOATUIPLZYQTFCFNNSNWKEJRMTTQIFWLTWGLJBBPPBUGKASKKFZVZKZXBLMHYLGFXRMLWYVJQOILMYZBHKUS9EZMGVGQHWXSVJEKAQVFLUIB9IP9LQZYGHAQLJLENO9IBSFOFIYHIBKOHEWVAEHKYOED9WBERCCLGGLOJVIZSIUUXGJ9WONIGBXKTVAWUXNHW999999999999999999999999999OOPS99999999999999999999999CAAZW9D99B99999999B99999999J9ZJXNHQVYKYPFUCPBPNDK9KDFDIGMFLZN9I9EV9XOWIYKEVE9LUSFXQLGBQBNHJPLU9ULJ9ZVR9HFOFW999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999OOPS99999999999999999999999999999999999999999999999999999999999999999999999999999";

static tryte_t const *const SEND_1K_HASH2 = (tryte_t *)"HZDCM9A9FT9USJFMDHODIEHWJPRLPMLFCJAPGVFUQOUIRKMPKUFZZYKLAZADT9DNXGSKWAEBCORORGOBW9GKXKELATELGJYXBBFDTCGVRHJXXUVSJXCMSHAELPTTZFBBHIUD9GHWGTQZDWR9HTVBCVILCKJUKAKMBX9XNY9TCFLOOWJZLRXHSKRVDUBPLY9RVMXBVLREIPYGINMQRHHDQCEZHTXQYWJX9ORYRYVZHRVTGTJ9XIAYSGA9FGFVUUSKVYWMTVFOABPFRYHLOVONNF9RKDLIJAHM9URWEKKWURNPZQNIGNRN9QBSLJTNWRNYQIGXHKXNI9VTMXKOMWFPBGYGBJ9DRMCDOBCXMUDLSWTW9LJFADJDZCTRZKJFDLOLKVJQKFDTCHNY9PCZUTNOAFSEKNPZMAUIECFRYFQRMTMNKGBLBAPVX9RIWRTHBIEZVXVJUMRVSPSW9MIQ9AQ9JVHGNI9CMIBOREULZXHTKZIVNHBOR9ZCPHQJSYFNRTYTDYO9STHXVXSWLAVAAAUJEZAJALWRJBWOQB99CSAUZAMWHHETQHYKIEZUVYYURFCTJ9DEW9ZXZUOKXVJJZRWRTZILWWVEKU9TEZMPFZEVLK9IZCRZLLWAKOCQZPRSDNAKNWO99JZCZWAOQESVDYWQIEU9AOGXAMYLUDMLN9FYM9NZJJWWOXIATMMHBCQHZHSARGGGKQLHDKCQSIFSTZVSIILF9UBMPRBJBGO9NRPHMOSYTSPDMPFLFKDZCZRHQFSTQASJJHYXHHBFXL9NRXBQLOWXHAGXNWVXGKARLJCVUXVHUNMMDUBO9OUNSDEQLYRUDYZNVFNVUOWABFPXVRREQHFCVBLNNBOPMDDXJOH9IDHUVSQFTUAIYHROUWBRFFCJCFMBTFXJUKBVDJI9RWIPPLSTBSGMMNKYAVBHMIJLCTJ9VDFNNUCKAWHQUWGCQCQKCCXHDWWXKPICZAWOYEPKJTIKJXSEGCRJNSQPBKJCSTARTKHLDITSERBMZAPPQEBGAWKLLCPAMMVAS9SRPSGPGLJXHRFBWGEFNQ9IYBZLRBMAKMYTIWMSDLRPULTGDV9OPVNY9DJZCPUETNIHKDZ9TVJUWOENUYW9HMYDGVLCIPYVYWTADOFCAFJELGCPBD9BEORSKPTFFTSNQRZSOZ9XST9LTQXJSROMUWKSHDZ9GHVIHTULDVTCGCWBJZMTGF9YDZXPYAGNOXUURXIFN99GYQIHNJDZLUNUPNILNUQVLAHEURDMN9IIHIFFGGBLMETSWMUYTTSJUWBCOLDDCKYYLYZMNLCCJRVWHPQQPNMAYLWAACVSZYNUCAAZEBHUILY9POSMJHTNKACEOQPOQYCKYMOFMIXMDLIECPOHJCONDEWRNURJHCXINKQCBFZMDONSQHHEIRDLZSEDVHIGVCJQVU9M9WAFVSZTHJBVZGGPTMSAIRJOOWTGJEEENBSUDHGDBGIQBASTAIOHCBBMSOIPJZMAOODLMBTVOHPJJJJTQHMLHUPILNUICTCT9DJRUHFBHI9MEIJOAXNKRTPMCPJFLYTVQRESYLJKPPOKURJWAAKVZQBT9ZJRBYJNZIWRRCQX9EGZZIXFCQ9ZOTHCFYOYZIGLCSKHOFUWGYCUASFP9XXFZXSUMIELOFFMBVLZMV9MXFDGUOWYKDTBOLRTUFSMVPQ9PDCBSBHCWEQBCBNYKNUNKHPHQX9CTTNYZKXCQMHGDXWKFVVQGKHEXL9MSEGEZGRSTPZGZJSD9YMSVMLGDMLPOLB9DGT9XASFPSPNQNRCMREKX9JECYZST999JCBLHFX9KHIMOMKMHBKENADVTROC9WBFCNXFYUIHQBZHLPYHZOUYGQBBQZPJUEOLYDXVMFJOTFQPZFZQPQVIKDJOFNBSBOQJMYZWJNAKMEIHBVGWOAFYJJFKWECSDOGBKFFKVNCZTODQWSQJKJZVHHTMGCWYSANL9FXHUXEQNFFHVVBSAZRECGYHMPUSKXEVOR9EXSAVCJARYVUZVKRKCDGVDYEMIOFSOYYXBBWGLH9ESJYMFBCCJETZDT9FNUH9YYXOPVPTRQOUBWZMGSDJT9BAGXONELIZVQBGCDLNQBBAVZUXBJPYBIGRACTKQYTYSGCPPMZOINCKFCGBTUTVXVGWFMLOMQOF9XGLYTTKNWLPMTPQKXLMFQQVWB9LQZYGHAQLJLENO9IBSFOFIYHIBKOHEWVAEHKYOED9WBERCCLGGLOJVIZSIUUXGJ9WONIGBXKTVAWUXNHWZQZ999999999999999999999999OOPS99999999999999999999999CAAZW9D99A99999999B99999999J9ZJXNHQVYKYPFUCPBPNDK9KDFDIGMFLZN9I9EV9XOWIYKEVE9LUSFXQLGBQBNHJPLU9ULJ9ZVR9HFOFW999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999OOPS99999999999999999999999999999999999999999999999999999999999999999999999999999";

static tryte_t const *const SEND_1K_HASH3 = (tryte_t *)"999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999PNRMSXRHPOFXERGZCCIOHBLXLCSROQXJINLUNDNLTKEMIISBYN9GWFOE9M9YOACEYCZA9NGAMMMFUHBADAJA999999999999999999999999FQPS99999999999999999999999BAAZW9D99999999999B99999999J9ZJXNHQVYKYPFUCPBPNDK9KDFDIGMFLZN9I9EV9XOWIYKEVE9LUSFXQLGBQBNHJPLU9ULJ9ZVR9HFOFW999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999OOPS99999999999999999999999999999999999999999999999999999999999999999999999999999";

