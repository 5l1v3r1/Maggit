
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


# constants dealing with ANSI color codes for the command line
CC_IN = '\033[92m'
CC_OUT = '\033[91m'
CC_NONE = '\033[0m'

class CommandInterface:
    '''
        Sets up the control application / tunnel control interface
    '''
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.needed = True
        while self.needed:
            # loops until we get a command to stop
            inp = raw_input("") # read a line
            if len(inp) == 0: # if the line is empty, skip
                continue
            elif inp.startswith('/'): #  if it starts with '/' we jump to run the command
                self.run_command(inp[1:])
            else:
                # put some data in the send queue
                print CC_OUT + '> '+str(inp)+'' + CC_NONE
                self.tunnel.send(inp)

    def run_command(self, cmd):
        # executing the commands
        if cmd == 'q' or cmd == 'quit':
            # quit application command
            print ': Quitting..'
            self.needed = False
        elif cmd == 'c' or cmd == 'connect':
            # the command to establish a CLIENT-SERVER connection, the other side becoming the SERVER
            print ': Initializing other side as server..'
            self.tunnel.send_switch_to_server()
        elif cmd.startswith('exec'):
            # remote command execution, returns the command output
            self.tunnel.send_command(cmd[4:])
        elif cmd == 'i' or cmd == 'info':
            # get current tunnel settings information
            self.tunnel.display_tunnel_info()
        elif cmd == 'pi' or cmd == 'packetinfo':
            # show last sent packet info
            self.tunnel.dump_packet_info()
        else:
            # unknown command
            print ': Unknown command!'

if __name__ == '__main__':
    # do nothing if run directly
    pass
