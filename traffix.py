import socket
import struct
import textwrap
##################
# SEC1: buffer size that is
# receive for each packet and 
# get common protocol names(complete source: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).
##################
BUF = 65535
PROTOCOLS = {1:'ICMP', 2:'IGMP', 6:'TCP', 9:'IGP',
			17:'UDP', 47:'GRE', 50:'ESP', 51:'AH',
			57:'SKIP', 88:'EIGRP', 115:'L2TP'}
##################
# SEC2: decode source and destination
# mac addresses.
##################
def parse_mac(mac_raw):
	byte_str = map('{:02x}'.format, mac_raw)
	mac_addr = ':'.join(byte_str).upper()
	return mac_addr
##################
# SEC3: Parse Ethernet Frames
##################
def ether_parse(raw_data):
	res = {}
	(dest, src, ether_type) = struct.unpack('! 6s 6s H', raw_data[:14])
	res['destination_mac'] = parse_mac(dest)
	res['source_mac'] = parse_mac(src)
	res['ethernet_type'] = socket.htons(ether_type)
	return raw_data[14:], res
##################
# SEC4: Parse Header IP
##################
def header_parse(raw_data):
	res = {}
	version_header_length = raw_data[0]
	res['version'] = version_header_length >> 4
	header_length = (version_header_length & 15) * 4
	(res['ttl'], pro, src, target) = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
	res['source_ip'] = '.'.join(map(str, src))
	res['destination_ip'] = '.'.join(map(str, target))
	res['header_length'] = str(header_length) + ' byte'
	try:
		res['source_hostname'] = socket.gethostbyaddr(res['source_ip'])[0]
	except:
		res['source_hostname'] = 'unknow'
	try:
		res['destination_hostname'] = socket.gethostbyaddr(res['destination_ip'])[0]
	except:
		res['destination_hostname'] = 'unknow'
	res['protocol'] = PROTOCOLS.get(pro, 'unknow')
	return raw_data[header_length:], res
##################
# SEC5: Parse TCP packets
##################
def tcp_parse(raw_data):
	res = {}
	(src_port, dest_port, sequence, acknowledgment, ORF) = struct.unpack(
		'! H H L L H', raw_data[:14])
	offset = (ORF >> 12) * 4
	res['src_port'] = src_port
	res['dest_port'] = dest_port
	res['sequence'] = sequence
	res['acknowledgment'] = acknowledgment
	offset = (ORF >> 12) * 4
	res['flag_urg'] = (ORF & 32) >> 5
	res['flag_ack'] = (ORF & 16) >> 4
	res['flag_psh'] = (ORF & 8) >> 3
	res['flag_rst'] = (ORF & 4) >> 2
	res['flag_syn'] = (ORF & 2) >> 1
	res['flag_fin'] = ORF & 1
	return raw_data[offset:], res
##################
# SEC6: Parse UDP packets
##################
def udp_parse(raw_data):
	res = {}
	(res['src_port'], res['dest_port'], res['size']) = struct.unpack('! H H 2x H', raw_data[:8])
	return raw_data[4:], res
##################
# SEC7: Parse ICMP packets
##################
def icmp_parse(raw_data):
	res = {}
	(res['type'], res['code'], res['checksum']) = struct.unpack('! B B H', raw_data[:4])
	return raw_data[4:], res
##################
# SEC8: Style packet content using textwrap module
##################
def textwrapping(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
##################
# SEC9: create an IPv4(0x0800) socket and wait
# for the traffic(send and receive packets).
# The recvfrom method in the socket module helps us to receive all the data from the socket. The
# parameter passed is the buffer size; 65565 is the maximum buffer size.
##################
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as conn:
	while True:
		(raw_data, addr) = conn.recvfrom(BUF)

		(raw_data, ether) = ether_parse(raw_data)
		print('Ethernet frame:')
		for i in ether:
			print(f"\t{i}: {ether[i]}")

		(raw_data, header) = header_parse(raw_data)
		print('Header:')
		for i in header:
			print(f"\t{i}: {header[i]}")
		protocol = header['protocol']

		if protocol == 'TCP':
			(data, tcp) = tcp_parse(raw_data)
			print('TCP:')
			for i in tcp:
				print(f"\t{i}: {tcp[i]}")
			if len(data) > 0:
				print('TCP data:')
				if 80 in (tcp['src_port'], tcp['dest_port']):
					try:
						data = data.decode('u8')
						for line in data.split('\n'):
							print(f"\t{line}")
					except:
						print(textwrapping('\t', data))
				else:
					print(textwrapping('\t', data))

		elif protocol == 'UDP':
			(data, udp) = udp_parse(raw_data)
			print('UDP:')
			for i in udp:
				print(f"\t{i}: {udp[i]}")
			print('UDP data:')
			print(textwrapping('\t', data))
		elif protocol == 'ICMP':
			(data, icmp) = icmp_parse(raw_data)
			print('ICMP:')
			for i in icmp:
				print(f"\t{i}: {icmp[i]}")
			print('ICMP data:')
			print(textwrapping('\t', data))
		else:
			print('Other Protocols:')
			print(textwrapping('\t', raw_data))
		print('-'*40)
