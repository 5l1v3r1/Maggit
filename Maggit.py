'''
@author: Armando Vega

Glavna aplikacija
'''
import argparse
import sys
import MaggitNetUtils as mNet
import MaggitDataUtils as mData
import MaggitCmdUtils as mCmd


if __name__ == '__main__':
    # arparse koristimo za generiranje helpa i parsiranje argumenata
    parser = argparse.ArgumentParser(description='ICMP tunnel with remote command execution')
    parser.add_argument('-d', '--destination', help='Destination IP address', required=True)
    parser.add_argument('-s', '--source', help='Source IP address (Default: 0.0.0.0)', required=False, default='0.0.0.0')
    parser.add_argument('-e', '--encryption', help='Encryption algorithm (Default: AES)', required=False, choices=['AES','ROT13', 'PLAIN'],  default='AES')
    parser.add_argument('-k', '--key', help='Encryption key/password (Default: "thisisapassword")', required=False, default='thisisapassword')
    
    # ako nema argumenata ispisi help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    else:
        params = parser.parse_args()
    
    # prebacivanje teksta u numerice konstante
    if params.encryption == 'AES':
        algo = mData.ALGO_AES
    elif params.encryption == 'ROT13':
        algo = mData.ALGO_ROT13
    else:
        algo = mData.ALGO_PLAIN
    
    # startamo novi kanal
    chan = mNet.ICMPChannel(src_ip_addr = params.source, dst_ip_addr=params.destination, algo=algo, password=params.key)
    chan.start()
    
    # predajemo kontrolu nad programom interfejsu
    mCmd.CommandInterface(chan)
    
    # zatvaramo kanal
    chan.close()

