
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


from impacket import ImpactDecoder, ImpactPacket
from threading import Thread 
import socket
from select import select
import MaggitDataUtils as mData
import MaggitCmdUtils as mCmd
import sys
import subprocess

# postavljamo neke konstante
CLIENT = 1
SERVER = 2

CLIENT_PREFIX = 'maggcli'
SERVER_PREFIX = 'maggser'
CMD_PREFIX = 'maggexe'
TUNNEL_STS = 'maggsts'
TUNNEL_RET = 'maggret'
TUNNEL_NOOP = 'maggno'

class ICMPChannel(Thread):
    '''
        Klasa koja handla ICMP komunikaciju, vrti se u odvojenom threadu
    '''
    def __init__(self, dst_ip_addr, src_ip_addr='0.0.0.0', algo=mData.ALGO_AES, password='thisisapassword'):
        Thread.__init__(self)
        self.dst_ip_addr = dst_ip_addr
        self.src_ip_addr = src_ip_addr
        self.algo = algo
        self.password = password
        
        # postavljamo pocetnu vrijednost ID/SEQ na 0
        self.seq_id = 0
        # u pocetku startamo kao CLIENT
        self.operating_as = CLIENT
        self.create_packet()
        
        # buffer sa podacima koji se trebaju poslati
        self.data_buffer = []
                
        # otvaramo raw socket
        self.tunnel_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.tunnel_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.connected = False
        # prikazujemo poruku sa informacijama o tunelu
        self.display_tunnel_info()
    
    def display_tunnel_info(self):
        # ispis podataka o tunelu
        message = 'Configured tunnel: '
        if self.operating_as == CLIENT:
            message += '(CLIENT)'
            message += self.src_ip_addr+' -> '+self.dst_ip_addr
            message += '(SERVER)'
        else:
            message += '(SERVER)'
            message += self.src_ip_addr+' -> '+self.dst_ip_addr
            message += '(CLIENT)'
        message += '  [ICMP,'
        if self.algo == mData.ALGO_AES:
            message += 'AES'
        elif self.algo == mData.ALGO_ROT13:
            message += 'ROT13'
        else:
            message += 'PLAINTEXT'
        message += ']'
        print message
        
        
    def create_packet(self):
        # IP paket
        self.ip = ImpactPacket.IP()
        # ICMP paket
        self.icmp = ImpactPacket.ICMP()
        if self.operating_as == CLIENT:
            # ako smo CLIENT koristimo ECHO, inace ECHOREPLY
            self.icmp.set_icmp_type(self.icmp.ICMP_ECHO)
        else:
            self.icmp.set_icmp_type(self.icmp.ICMP_ECHOREPLY)
            self.ip.set_ip_ttl(64) # emulacija linux OS-a
        self.ip.set_ip_src(self.src_ip_addr)
        self.ip.set_ip_dst(self.dst_ip_addr)
            
        
    def run(self):
        # glavna metoda koja se pokrece sa start() (nasljedje od Threada)
        self.is_open = True
        while self.is_open:
            # vrtimo glavnu petlju dok se ne pozove close()
            r = select([self.tunnel_sock],[],[],1)[0]
            if self.tunnel_sock in r:
                # ako ima nesto za citanje na nasem socketu
                inbound = self.tunnel_sock.recvfrom(2000)[0]
                # raspakiravamo paket
                inbound_ip = ImpactDecoder.IPDecoder().decode(inbound)
                inbound_icmp = inbound_ip.child()
                
                try:
                    # pokusavamo dekriptirai paket, ako dodje do greske zbog nedostatka paddinga ocito nije nas paket
                    data = mData.DataMangler(inbound_icmp.get_data_as_string()).deobfuscate(self.password, self.algo)
                except:
                    # not the droid we are looking for
                    pass
                
                if self.operating_as == CLIENT:
                    # ako smo u CLIENT modu
                    if inbound_ip.get_ip_src() == self.dst_ip_addr and inbound_icmp.get_icmp_type() == self.icmp.ICMP_ECHOREPLY:
                        # ako odgovara SRC, DST IP i tip paketa
                        if data.startswith(SERVER_PREFIX):
                            # ako podaci pocinju sa prefixom poruke od servera
                            if data[len(SERVER_PREFIX):].startswith(CMD_PREFIX):
                                # ako je u podacima zapakirana naredba vadimo je van
                                command = data[len(SERVER_PREFIX)+len(CMD_PREFIX):]
                                try:
                                    # pokusavamo izvrsiti naredbu i uhvatiti output
                                    cmd_output = subprocess.check_output(command.split(' '))
                                except:
                                    # doslo je do problema pri izrsavanju naredbe
                                    cmd_output = "Command execution error!"
                                self.send_raw(cmd_output)
                            else:
                                # dobili smo ciste podatke, ispisi ih u konzolu
                                print mCmd.CC_IN + "< " + data[len(SERVER_PREFIX):] + mCmd.CC_NONE
                        elif data.startswith(TUNNEL_NOOP):
                            # ako server kaze da nema nista za nas spavamo
                            if not self.connected:
                                # ako nismo do sada imali ostvareni tunel oznacavamo ga kao ostvarenog
                                self.connected = True
                                print '\n: Tunnel operational!'
                elif self.operating_as == SERVER:
                    # ako smo u SERVER modu
                    if inbound_ip.get_ip_src() == self.dst_ip_addr and inbound_icmp.get_icmp_type() == self.icmp.ICMP_ECHO:
                        if data.startswith(CLIENT_PREFIX):
                            # ako su podaci od klijenta uzimamo ID/SEQ da mozemo pravilno craftati paket za odgovor
                            self.seq_id = inbound_icmp.get_icmp_id()
                            self.create_packet()
                            if data[len(CLIENT_PREFIX):].startswith(CMD_PREFIX):
                                # vadimo naredbu iz podataka
                                command = data[len(CLIENT_PREFIX)+len(CMD_PREFIX):]
                                try:
                                    # pokusavamo izvrsiti naredbu i uhvatiti output
                                    cmd_output = subprocess.check_output(command.split(' '))
                                except:
                                    # doslo je do problema pri izrsavanju naredbe
                                    cmd_output = "Command execution error!"
                                self.send_raw(cmd_output)
                            else:
                                # ispisujemo ciste podatke u konzolu
                                print mCmd.CC_IN + "< " + data[len(CLIENT_PREFIX):] + mCmd.CC_NONE
                        elif data.startswith(TUNNEL_RET):
                            # dobili smo zahtjev za slanje podataka na cekanju
                            self.seq_id = inbound_icmp.get_icmp_id()
                            self.create_packet()
                            if len(self.data_buffer) > 0:
                                # ako imamo podataka u bufferu skidamo jedan po jedan i saljemo
                                data = self.data_buffer.pop()
                                self.send_raw(data)
                            else:
                                # nemamo podataka za slanje, saljemo NOOP instrukciju
                                self.send_raw(TUNNEL_NOOP)
                            
                
                if inbound_icmp.get_icmp_type() == self.icmp.ICMP_ECHO:
                    if data == TUNNEL_STS:
                        # dobili smo komandu za prelazak u SERVER mod
                        try:
                            # lokalni dst = dolazni src, src = dst
                            self.dst_ip_addr = inbound_ip.get_ip_src()
                            self.src_ip_addr = inbound_ip.get_ip_dst()
                            self.seq_id = inbound_icmp.get_icmp_id()
                            self.operating_as = SERVER
                            # iskljucujemo handling ICMP ECHO paketa od sustava i preuzimamo na sebe (Linux)
                            f = open('/proc/sys/net/ipv4/icmp_echo_ignore_all','w')
                            f.write('1')
                            f.close()
                            # kreiramo novi paket sa novim podacima
                            self.create_packet()
                            # prikazujemo nove postavke tunela
                            self.display_tunnel_info()
                        except:
                            # ako ne uspijemo iskljuciti ECHO handling u sustavu odustajemo, preveliki pingstorm se dogodi od bouncanja
                            print 'Unable to switch to a clean server, quitting..'
                            self.close()
                            sys.exit(1)
            else:
                if self.operating_as == CLIENT:
                    # slanje upita serveru ako ima nesto novo za nas, zaobilazenje NATa/Firewalla
                    self.send_retrieve_data()
                
    def send_raw(self, data):
        # posljednja obrada podataka prije slanja
        if data not in [TUNNEL_STS, TUNNEL_RET, TUNNEL_NOOP]:
            # ako podaci nisu SwitchToServer niti Retrieve/NOOP naredbe
            # dodajemo CLIENT/SERVER prefixe ovisno o trenutnom modu rada
            if self.operating_as == CLIENT:
                data = CLIENT_PREFIX + data
            else:
                data = SERVER_PREFIX + data
        cipher = mData.DataMangler(data) # kreiramo novi kriptoobjekt
        # podaci se u kriptoobjektu kriptiraju sa odabranim passwordom i algoritmom,
        # uzima se samo prvih 1408 znakova (Ethernet ogranicenje 1500 bytes frame size, broj mora biti djeljiv sa 16 zbog AESa) i stavlja u ICMP data polje
        self.icmp.contains(ImpactPacket.Data(cipher.obfuscate(self.password, self.algo)[:1408]))
        # Uvecavamo ICMP paketu ID samo ako smo klijent
        if self.operating_as == CLIENT:
            self.seq_id += 1
            if self.seq_id > 65535:
                # ID je samo 2 byta, treba paziti na preljev
                self.seq_id = 0
        # vrijednost iz seq_id postavljamo i u ID polje i u SEQ polje
        self.icmp.set_icmp_id(self.seq_id)
        self.icmp.set_icmp_seq(self.seq_id)
        # automatsko racunanje checkshuma
        self.icmp.set_icmp_cksum(0)
        self.icmp.auto_checksum = 1
        # ICMP paket pakira se u IP paket
        self.ip.contains(self.icmp)
        # saljemo finalni paket
        self.tunnel_sock.sendto(self.ip.get_packet(), (self.dst_ip_addr, 0))
    
    def send(self, data):
        if self.operating_as == CLIENT:
            # ako smo klijent saljemo podatke direktno
            self.send_raw(data)
        else:
            # ako smo server, stavljamo podatke u red za slanje
            self.data_buffer.append(data)

    def send_switch_to_server(self):
        # slanje drugoj strani naredbe za prelazak u SERVER mod rada
        self.connected = False
        self.send_raw(TUNNEL_STS)
    
    def send_retrieve_data(self):
        # slanje naredbe za dohvat podataka (firewall/NAT zaobilazak)
        self.send_raw(TUNNEL_RET)
    
    def send_command(self, command):
        # slanje komande za izvrsavanje na drugoj strani
        cmd = command.strip()
        self.send(CMD_PREFIX+cmd)
    
    def dump_packet_info(self, packet=None):
        # ispis podataka o posljednjem poslanom paketu, debug funkcija
        if packet == None:
            ip = self.ip
            icmp = self.icmp
        else:
            ip = packet
            icmp = packet.child()
        print 'SRC: ' + ip.get_ip_src()
        print 'DST: ' + ip.get_ip_dst()
        print 'ITYPE: ' + str(icmp.get_icmp_type())
        print 'ISEQ: ' + str(icmp.get_icmp_id())
    
    def close(self):
        # zatvaranje tunela
        if self.operating_as == SERVER:
            # ako smo server vracamo sustavu kontrolu nad ICMP ECHO paketima
            f = open('/proc/sys/net/ipv4/icmp_echo_ignore_all','w')
            f.write('0')
            f.close()
        # gasimo glavnu while petlju
        self.is_open = False

if __name__ == '__main__':
    # ako modul nije includean nego se pozove sam ne radi nista
    pass
    
