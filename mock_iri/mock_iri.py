#! /usr/bin/env python3

from flask import Flask, render_template, request
import json
import re

app = Flask(__name__)


@app.route("/", methods=['POST'])
def iota_api():
    # print(request.headers)

    if request.headers['Content-Type'] != "application/json":
        return json.dumps({'Err': 'Content-Type : {} is not match'.format(request.headers['Content-Type'])})
    if request.headers['X-IOTA-API-Version'] != "1":
        return json.dumps({'Err': 'X-IOTA-API-Version : {} is not match'.format(request.headers['X-IOTA-API-Version'])})
    print("POST: {}".format(request.data))
    res = dummpy_response(request.get_json())
    print("\nRES: {}".format(res))
    return res


def dummpy_response(data):
    cmd = data['command']
    if cmd == "getNodeInfo":
        strR = """{
		"appName": "IRI",
		"appVersion": "1.0.8.nu",
		"duration": 1,
		"jreAvailableProcessors": 4,
		"jreFreeMemory": 91707424,
		"jreMaxMemory": 1908932608,
		"jreTotalMemory": 122683392,
		"latestMilestone": "VBVEUQYE99LFWHDZRFKTGFHYGDFEAMAEBGUBTTJRFKHCFBRTXFAJQ9XIUEZQCJOQTZNOOHKUQIKOY9999",
		"latestMilestoneIndex": 107,
		"latestSolidSubtangleMilestone": "VBVEUQYE99LFWHDZRFKTGFHYGDFEAMAEBGUBTTJRFKHCFBRTXFAJQ9XIUEZQCJOQTZNOOHKUQIKOY9999",
		"latestSolidSubtangleMilestoneIndex": 107,
		"neighbors": 2,
		"packetsQueueSize": 0,
		"time": 1477037811737,
		"tips": 3,
		"transactionsToRequest": 0
	    }\n"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())

    if cmd == "getNeighbors":
        strR = """{
		"duration": 37,
		"neighbors": [
		{
		    "address": "/8.8.8.8:14265",
		    "numberOfAllTransactions": 922,
		    "numberOfInvalidTransactions": 0,
		    "numberOfNewTransactions": 92
		},
		{
		    "address": "/8.8.8.8:5000",
		    "numberOfAllTransactions": 925,
		    "numberOfInvalidTransactions": 0,
		    "numberOfNewTransactions": 20
		}
		]
	    }"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())

    if cmd == "checkConsistency":
        strR = '{"error":"No URIs"}'
        if data['tails']:
            strR = """{
                    "state": false, 
                    "info": "", 
                    "duration": 2
                }"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())
    if cmd == "addNeighbors":
        strR = '{"error":"No URIs"}'
        if data['uris']:
            strR = """{
                    "addedNeighbors": 9,
                    "duration": 2
                }"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())

    if cmd == "removeNeighbors":
        strR = '{"error":"No URIs"}'
        if data['uris']:
            strR = """{
                    "removedNeighbors": 2, 
                    "duration": 2
                }"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())

    if cmd == "getTips":
        strR = """{
		"hashes": 
		["YVXJOEOP9JEPRQUVBPJMB9MGIB9OMTIJJLIUYPM9YBIWXPZ9PQCCGXYSLKQWKHBRVA9AKKKXXMXF99999", "ZUMARCWKZOZRMJM9EEYJQCGXLHWXPRTMNWPBRCAGSGQNRHKGRUCIYQDAEUUEBRDBNBYHAQSSFZZQW9999", "QLQECHDVQBMXKD9YYLBMGQLLIQ9PSOVDRLYCLLFMS9O99XIKCUHWAFWSTARYNCPAVIQIBTVJROOYZ9999"], 
		"duration": 4
	    }"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())

    if cmd == "findTransactions":
        strR = '{"error":"No address"}'
        if data['addresses']:
            strR = """{
		    "hashes": ["ZJVYUGTDRPDYFGFXMKOTV9ZWSGFK9CFPXTITQLQNLPPG9YNAARMKNKYQO9GSCSBIOTGMLJUFLZWSY9999", "9999UGTDRPDYFGFXMKOTV9ZWSGFK9CFPXTITQLQNLPPG9YNAARMKNKYQO9GSCSBIOTGMLJUFLZWSY9999"] 
		}"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())

    if cmd == "getTrytes":
        strR = '{"error":"No hashes"}'
        if data['hashes']:
            strR = """{
		    "trytes": [ "BYSWEAUTWXHXZ9YBZISEK9LUHWGMHXCGEVNZHRLUWQFCUSDXZHOFHWHL9MQPVJXXZLIXPXPXF9KYEREFSKCPKYIIKPZVLHUTDFQKKVVBBN9ATTLPCNPJDWDEVIYYLGPZGCWXOBDXMLJC9VO9QXTTBLAXTTBFUAROYEGQIVB9MJWJKXJMCUPTWAUGFZBTZCSJVRBGMYXTVBDDS9MYUJCPZ9YDWWQNIPUAIJXXSNLKUBSCOIJPCLEFPOXFJREXQCUVUMKSDOVQGGHRNILCO9GNCLWFM9APMNMWYASHXQAYBEXF9QRIHIBHYEJOYHRQJAOKAQ9AJJFQ9WEIWIJOTZATIBOXQLBMIJU9PCGBLVDDVFP9CFFSXTDUXMEGOOFXWRTLFGV9XXMYWEMGQEEEDBTIJ9OJOXFAPFQXCDAXOUDMLVYRMRLUDBETOLRJQAEDDLNVIRQJUBZBO9CCFDHIX9MSQCWYAXJVWHCUPTRSXJDESISQPRKZAFKFRULCGVRSBLVFOPEYLEE99JD9SEBALQINPDAZHFAB9RNBH9AZWIJOTLBZVIEJIAYGMC9AZGNFWGRSWAXTYSXVROVNKCOQQIWGPNQZKHUNODGYADPYLZZZUQRTJRTODOUKAOITNOMWNGHJBBA99QUMBHRENGBHTH9KHUAOXBVIVDVYYZMSEYSJWIOGGXZVRGN999EEGQMCOYVJQRIRROMPCQBLDYIGQO9AMORPYFSSUGACOJXGAQSPDY9YWRRPESNXXBDQ9OZOXVIOMLGTSWAMKMTDRSPGJKGBXQIVNRJRFRYEZ9VJDLHIKPSKMYC9YEGHFDS9SGVDHRIXBEMLFIINOHVPXIFAZCJKBHVMQZEVWCOSNWQRDYWVAIBLSCBGESJUIBWZECPUCAYAWMTQKRMCHONIPKJYYTEGZCJYCT9ABRWTJLRQXKMWY9GWZMHYZNWPXULNZAPVQLPMYQZCYNEPOCGOHBJUZLZDPIXVHLDMQYJUUBEDXXPXFLNRGIPWBRNQQZJSGSJTTYHIGGFAWJVXWL9THTPWOOHTNQWCNYOYZXALHAZXVMIZE9WMQUDCHDJMIBWKTYH9AC9AFOT9DPCADCV9ZWUTE9QNOMSZPTZDJLJZCJGHXUNBJFUBJWQUEZDMHXGBPTNSPZBR9TGSKVOHMOQSWPGFLSWNESFKSAZY9HHERAXALZCABFYPOVLAHMIHVDBGKUMDXC9WHHTIRYHZVWNXSVQUWCR9M9RAGMFEZZKZ9XEOQGOSLFQCHHOKLDSA9QCMDGCGMRYJZLBVIFOLBIJPROKMHOYTBTJIWUZWJMCTKCJKKTR9LCVYPVJI9AHGI9JOWMIWZAGMLDFJA9WU9QAMEFGABIBEZNNAL9OXSBFLOEHKDGHWFQSHMPLYFCNXAAZYJLMQDEYRGL9QKCEUEJ9LLVUOINVSZZQHCIKPAGMT9CAYIIMTTBCPKWTYHOJIIY9GYNPAJNUJ9BKYYXSV9JSPEXYMCFAIKTGNRSQGUNIYZCRT9FOWENSZQPD9ALUPYYAVICHVYELYFPUYDTWUSWNIYFXPX9MICCCOOZIWRNJIDALWGWRATGLJXNAYTNIZWQ9YTVDBOFZRKO9CFWRPAQQRXTPACOWCPRLYRYSJARRKSQPR9TCFXDVIXLP9XVL99ERRDSOHBFJDJQQGGGCZNDQ9NYCTQJWVZIAELCRBJJFDMCNZU9FIZRPGNURTXOCDSQGXTQHKHUECGWFUUYS9J9NYQ9U9P9UUP9YMZHWWWCIASCFLCMSKTELZWUGCDE9YOKVOVKTAYPHDF9ZCCQAYPJIJNGSHUIHHCOSSOOBUDOKE9CJZGYSSGNCQJVBEFTZFJ9SQUHOASKRRGBSHWKBCBWBTJHOGQ9WOMQFHWJVEG9NYX9KWBTCAIXNXHEBDIOFO9ALYMFGRICLCKKLG9FOBOX9PDWNQRGHBKHGKKRLWTBEQMCWQRLHAVYYZDIIPKVQTHYTWQMTOACXZOQCDTJTBAAUWXSGJF9PNQIJ9AJRUMUVCPWYVYVARKR9RKGOUHHNKNVGGPDDLGKPQNOYHNKAVVKCXWXOQPZNSLATUJT9AUWRMPPSWHSTTYDFAQDXOCYTZHOYYGAIM9CELMZ9AZPWB9MJXGHOKDNNSZVUDAGXTJJSSZCPZVPZBYNNTUQABSXQWZCHDQSLGK9UOHCFKBIBNETK999999999999999999999999999999999999999999999999999999999999999999999999999999999NOXDXXKUDWLOFJLIPQIBRBMGDYCPGDNLQOLQS99EQYKBIU9VHCJVIPFUYCQDNY9APGEVYLCENJIOBLWNB999999999XKBRHUD99C99999999NKZKEKWLDKMJCI9N9XQOLWEPAYWSH9999999999999999999999999KDDTGZLIPBNZKMLTOLOXQVNGLASESDQVPTXALEKRMIOHQLUHD9ELQDBQETS9QFGTYOYWLNTSKKMVJAUXSIROUICDOXKSYZTDPEDKOQENTJOWJONDEWROCEJIEWFWLUAACVSJFTMCHHXJBJRKAAPUDXXVXFWP9X9999IROUICDOXKSYZTDPEDKOQENTJOWJONDEWROCEJIEWFWLUAACVSJFTMCHHXJBJRKAAPUDXXVXFWP9X9999"] 
		}"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())

    if cmd == "getInclusionStates":
        strR = '{"error":"No transactions or tips"}'
        if data['transactions'] and data['tips']:
            strR = """{
		    "states": [true, false, true], 
		    "duration": 91
		}"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())

    if cmd == "getBalances":
        strR = '{"error":"No Addresses"}'
        # if data['addresses'] and data['threshold']:
        if data['addresses']:
            strR = """{
		    "balances": [
		    "114544444",
            "100",
            "0"
		    ],
		    "duration": 30,
		    "references": ["INRTUYSZCWBHGFGGXXPWRWBZACYAFGVRRP9VYEQJOHYD9URMELKWAFYFMNTSP9MCHLXRGAFMBOZPZ9999"],
		    "milestoneIndex": 128
		}"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())

    if cmd == "getTransactionsToApprove":
        strR = '{"error":"No depth"}'
        if data['depth']:
            strR = """{
		    "trunkTransaction": "TKGDZ9GEI9CPNQGHEATIISAKYPPPSXVCXBSR9EIWCTHHSSEQCD9YLDPEXYERCNJVASRGWMAVKFQTC9999", 
		    "branchTransaction": "TKGDZ9GEI9CPNQGHEATIISAKYPPPSXVCXBSR9EIWCTHHSSEQCD9YLDPEXYERCNJVASRGWMAVKFQTC9999", 
		    "duration": 936
		}"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())
    if cmd == "attachToTangle":
        strR = '{"error":"Params Error"}'
        if data['trunkTransaction'] and data['branchTransaction'] and data['minWeightMagnitude'] and data['trytes']:
            strR = """{
                    "trytes":["TRYTEVALUEHERE1", "TRYTEVALUEHERE2", "TRYTEVALUEHERE3"],
		    "duration": 936
		}"""
        return "".join(re.sub(r'(^[ \t]+|[ \t]+(?=:))', '', strR, flags=re.M).split())
    if cmd == "broadcastTransactions":
        print("broadcastTransactions")
        return "{ }"
    if cmd == "storeTransactions":
        print("storeTransactions")
        return "{ }"
    print("CMD not match")
    return '{"error":"unknow command"}'


def flaskrun(app, default_host="127.0.0.1",
             default_port="14265"):
    """
    Takes a flask.Flask instance and runs it. Parses 
    command-line flags to configure the app.
    """
    import optparse

    # Set up the command-line options
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host",
                      help="Hostname of the Flask app " +
                           "[default %s]" % default_host,
                      default=default_host)
    parser.add_option("-P", "--port",
                      help="Port for the Flask app " +
                           "[default %s]" % default_port,
                      default=default_port)

    # Two options useful for debugging purposes, but
    # a bit dangerous so not exposed in the help message.
    parser.add_option("-d", "--debug",
                      action="store_true", dest="debug",
                      help=optparse.SUPPRESS_HELP)
    parser.add_option("-p", "--profile",
                      action="store_true", dest="profile",
                      help=optparse.SUPPRESS_HELP)

    options, _ = parser.parse_args()

    # If the user selects the profiling option, then we need
    # to do a little extra setup
    if options.profile:
        from werkzeug.contrib.profiler import ProfilerMiddleware

        app.config['PROFILE'] = True
        app.wsgi_app = ProfilerMiddleware(app.wsgi_app,
                                          restrictions=[30])
        options.debug = True

    app.run(
        debug=options.debug,
        host=options.host,
        port=int(options.port)
    )


if __name__ == '__main__':
    flaskrun(app)
