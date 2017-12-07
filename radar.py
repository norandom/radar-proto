from optparse import OptionParser

from qradar.qradar_bridge import *
from qradar.qradar_filters import *
from xforce.feed_bridge import *

import pdb


# this is from your ini file
qradar_section = "QRADAR"
xforce_section = "XFORCE"

# pandas, pygments


def main():
    cfg = read_config(cfgname="config.ini", section=qradar_section)
    print "QRadar config parsed. Check!"

    server_ip = cfg.get(qradar_section, "server_ip")
    print "Making requests to QRadar @ " + server_ip
    print "-" * 3

    token = cfg.get(qradar_section, "auth_token")
    usern = cfg.get(qradar_section, "user")
    passw = cfg.get(qradar_section, "password")

    read_config(cfgname="config.ini", section=xforce_section)
    xforce_api_key = cfg.get(xforce_section, "api_key")
    xforce_api_pw  = cfg.get(xforce_section, "api_pw")
    xforce_endpoint = cfg.get(xforce_section, "ibm_url")
    print "Making requests to Xforce @ " + xforce_endpoint


    parser = OptionParser()
    parser.add_option("-d", "--get-qdbs", dest="getqdbs",
                      help="Get QRadar DBs")
    parser.add_option("-o", "--get-offenses", dest="getqoff",
                      help="Get QRadar Offenses")
    parser.add_option("-a", "--get-offense-ips", dest="getqoffips",
                      help="Get QRadar Offense IPs as list of unique values")
    parser.add_option("-g", "--ariel-query", dest="qq",
                      help="Make a QRadar Ariel query and print the results")
    parser.add_option("-x", "--xforce-iplookup", dest="xforceip",
                      help="Lookup some IP threat information via IBM Xforce")

    parser.add_option("-q", "--quiet", dest="verbose", default=False,
                      help="Print verbose status messages to stdout")
    (options, args) = parser.parse_args()

    if options.getqdbs:
        print "Getting QRadar DBs..."
        q_dbs = ariel_request_dbs(server_ip, usern, passw, token)
        print "We found the following Ariel DBs: " + str(q_dbs) + " @ " + server_ip

    if options.getqoff:
        offenses = get_offenses(server_ip, usern, passw, token)
        print offenses

    if options.getqoffips:
        ips = get_offense_ips(offenses)
        print str(ips)

    if options.xforceip:
        threat_intel = get_threat_intel_by_ip("8.8.8.8", xforce_api_key, xforce_api_pw, xforce_endpoint)
        print threat_intel

        #threat_intel = get_reputation_by_ip("8.8.8.8", xforce_api_key, xforce_api_pw, xforce_endpoint)
        #print threat_intel

        score = get_threat_score_by_ip("8.8.8.8", xforce_api_key, xforce_api_pw, xforce_endpoint)
        print "Sc00re is: " + str(score)


    if options.qq:
        log_results = ariel_query(server_ip, usern, passw, token, query='SELECT * FROM events LAST 15 MINUTES', keyword="events")
        print "-" * 22
        print "Log Results: "
        print log_results.head(10)

        flow_results = ariel_query(server_ip, usern, passw, token, query='SELECT * FROM flows LAST 15 MINUTES', keyword="flows")
        print "-" * 22
        print "Flow Results: "
        print flow_results.head(10)
        pdb.set_trace()

    print "---"


if __name__ == "__main__":
    main()