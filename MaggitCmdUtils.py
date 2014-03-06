'''
@author: Armando Vega

Modul koji sadrzi klase i konstante potrebne za rad sa komandnom linijom
'''

# konstante koje barataju sa ANSI color kodovima za bojanje komandne linije
CC_IN = '\033[92m'
CC_OUT = '\033[91m'
CC_NONE = '\033[0m'

class CommandInterface:
    '''
        Klasa koja pruza kontrolno sucelje nad aplikacijom/tunelom
    '''
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.needed = True
        while self.needed:
            # glavna petlja se vrti do naredbe za prekid
            inp = raw_input("") # ucitavamo red
            if len(inp) == 0: # ako je red prazan preskacemo akciju
                continue
            elif inp.startswith('/'): # ako pocinje sa / skacemo na obradu naredbe
                self.run_command(inp[1:])
            else:
                # stavljamo podatke u red za slanje
                print CC_OUT + '> '+str(inp)+'' + CC_NONE
                self.tunnel.send(inp)

    def run_command(self, cmd):
        # izvrsavanje naredbi
        if cmd == 'q' or cmd == 'quit':
            # naredba za izlaz iz aplikacije
            print ': Quitting..'
            self.needed = False
        elif cmd == 'c' or cmd == 'connect':
            # naredba za ostvarivanja CLIENT-SERVER veze, druga strana postaje SERVER
            print ': Initializing other side as server..'
            self.tunnel.send_switch_to_server()
        elif cmd.startswith('exec'):
            # naredba za slanje naredbe koja ce se izvrsiti na drugoj strani tunela i vratiti output
            self.tunnel.send_command(cmd[4:])
        elif cmd == 'i' or cmd == 'info':
            # naredba koja prikazuje informacije o trenutnim postavkama tunela
            self.tunnel.display_tunnel_info()
        elif cmd == 'pi' or cmd == 'packetinfo':
            # naredba koja prikazuje informacije o posljednjem poslanom paketu
            self.tunnel.dump_packet_info()
        else:
            # naredba nije prepoznata
            print ': Unknown command!'

if __name__ == '__main__':
    # ako modul nije includean nego se pozove sam ne radi nista
    pass