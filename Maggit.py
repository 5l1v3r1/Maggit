
#  This file is part of Maggit.
#  
#  Maggit - ICMP tunneling for fun and no profit
#  Copyright (C) 2014 Armando Vega
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.


import argparse
import sys
import MaggitNetUtils as mNet
import MaggitDataUtils as mData
import MaggitCmdUtils as mCmd


if __name__ == '__main__':
    # use argparse for argument parsing
    parser = argparse.ArgumentParser(description='ICMP tunnel with remote command execution')
    parser.add_argument('-d', '--destination', help='Destination IP address', required=True)
    parser.add_argument('-s', '--source', help='Source IP address (Default: 0.0.0.0)', required=False, default='0.0.0.0')
    parser.add_argument('-e', '--encryption', help='Encryption algorithm (Default: AES)', required=False, choices=['AES','ROT13', 'PLAIN'],  default='AES')
    parser.add_argument('-k', '--key', help='Encryption key/password (Default: "thisisapassword")', required=False, default='thisisapassword')
    
    # if there are no arguments, print out help / usage
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    else:
        params = parser.parse_args()
    
    # set up the algo to be used
    if params.encryption == 'AES':
        algo = mData.ALGO_AES
    elif params.encryption == 'ROT13':
        algo = mData.ALGO_ROT13
    else:
        algo = mData.ALGO_PLAIN
    
    # start a new channel
    chan = mNet.ICMPChannel(src_ip_addr = params.source, dst_ip_addr=params.destination, algo=algo, password=params.key)
    chan.start()
    
    # hand over control to the interface module
    mCmd.CommandInterface(chan)
    
    # close the channel
    chan.close()

