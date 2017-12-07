import socket
import unicodedata


def get_offense_sources(offenses):
    for offense in offenses:
        print offense[u'offense_source']

def get_offense_ips(offenses):
    IP = []
    for offense in offenses:
        offense = dict(offense)
        ip = offense.get(u'offense_source')
        ip = unicodedata.normalize('NFKD', ip).encode('ascii','ignore')

        exceptions = ["192.168.1.", "10.0."]

        if valid_ip(ip):
            if ip not in exceptions:
                IP.append(ip)
    return set(IP)


def valid_ip(address):
    try:
        # print "Testing :" + address
        socket.inet_aton(address)
        return True
    except:
        return False
