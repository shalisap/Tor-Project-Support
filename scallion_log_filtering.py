#!/usr/bin/python2.7

'''
	Filters scallion.log for streams from fileclient to 
	fileserver.
'''

import re

'''
	Extracts the host name and ip addresses from scallion.log and 
	returns a dictionary of {name:ip address}.
'''
def get_ip_addresses():
	ip_addresses = {}
	with open("scallion.log") as f:
		for line in f:
			if "Created Host" in line:

				# find name and ip address of host
				try:
					name = re.search("'(.+?)'", line).group(1)
					ip_addr = re.search("ip (.+?),", line).group(1)

				except AttributeError:
					print "'Created Host' found with either no host name or ip address."
 
				ip_addresses[name] = ip_addr
	return ip_addresses

'''
	Given the ip address of a single fileclient,
	returns the circuits built by that client
	in a dictionary of {circuit id: circuit}, where
	circuit is a list of [fileclient, relay1, relay2, relay3, fileserver].
	May have to adjust for multiple fileclients. 
'''
def get_circuit_info(ip_addr_dict):
	circuit_dict = {}
	fileclient_ip_addr = ip_addr_dict['fileclient']
	fileserver_ip_addr = ip_addr_dict['fileserver']
	circuit_dict['fileclient'] = fileclient_ip_addr
	with open("scallion.log") as f:
		for line in f:
			if ("fileclient-" + fileclient_ip_addr in line and 
				"BUILT" in line):

				# find the circuit id and relays in the circuit
				try:
					circ_id = re.search("CIRC (.+?) BUILT", line).group(1)
					circ = re.search("~(.+?) ", line).group(1)
					circ = re.split(r'\W+', circ)
					for i in circ:
						if i not in ip_addr_dict.keys():
							circ.remove(i)

				except AttributeError:
					print "Could not find either the circuit id or host names of this circuit"

				circuit_dict[circ_id] = [ip_addr_dict[relay] for relay in circ]
				circuit_dict[circ_id].insert(0, fileclient_ip_addr)
				circuit_dict[circ_id].append(fileserver_ip_addr)

	return circuit_dict

'''
	Given a string in the shadow log format
	"real_time [thread-id] virtual_time [logdomain-loglevel] [hostname-ip] [function-name] MESSAGE"
	example: "00:00:16:020738 [thread-2] 00:20:00:450044072 [tor-message] [relay2-11.0.0.6] [scalliontor_logmsg_cb] RRCO: 11.0.0.3 -> 11.0.0.9 (2147495446 -> 10633)"

	Returns a filtered version of the string in the format 
	"virtual_time [hostname-ip] MESSAGE"
	example: "00:20:00:450044072 [relay2-11.0.0.6] RRCO: 11.0.0.3 -> 11.0.0.9 (2147495446 -> 10633)"
'''
def filter_log_message(line):

	try:
		virtual_time = re.search("\] (.+?) \[tor-message\]", line).group(1)
		relay_info = re.search("message\] (.+?) \[scalliontor", line).group(1)
		message = re.search("logmsg_cb\] (.+)", line).group(1)
	except AttributeError:
		print ("String not in the correct format (real_time [thread-id] " +
				"virtual_time [logdomain-loglevel] [hostname-ip] " +
 				"[function-name] MESSAGE) or missing parts")
	return virtual_time + " " + relay_info + " " + message + "\n"
			

'''
	Logs STREAM circ_id SUCCEEDED to STREAM circ_id CLOSED for 
	a single fileclient.
'''
def get_stream_messages(ip_addr_dict, circuit_dict):
	
	print_dict = {}
	record_flag = False
	circ_id = ""
	fileclient_ip_addr = ip_addr_dict['fileclient']

	with open("scallion.log", 'r') as f, open("filtered_scallion.log", "w") as f_out:
		for line in f:
			if ("fileclient-" + fileclient_ip_addr in line
				 and "SUCCEEDED" in line):
				
				# find the circuit being used in the stream
				try:
					circ_id = re.search("SUCCEEDED (.+?) ", line).group(1)
				except AttributeError:
					print ("Could not find the circuit id of circuit" +
							 "this stream is using")

				# initialize {relay_ip : []} for all relays in 
				# circuit circ_id.
				for i in circuit_dict[circ_id]:
					 print_dict[i] = []

				f_out.write("\n" + line)
				f_out.write("Circuit " + str(circ_id) + " : " +
							 str(circuit_dict[circ_id]) + "\n")
				record_flag = True

			elif ("fileclient-" + fileclient_ip_addr in line
				 and "CLOSED" in line and "STREAM" in line):

				# write things out before closing and reset all values
				for relay in circuit_dict[circ_id]:
					if print_dict[relay] != []: 
						f_out.write("\n-----" + relay + "-----\n")
						relay_lines = print_dict[relay]
						for r_line in relay_lines:
							f_out.write(r_line)
					
				f_out.write("\n" + line + "\n")
				record_flag = False
				print_dict = {}
				circ_id = ""
                                                                                
			if (record_flag == True and "RRC" in line):	

				try:
					p_relay = re.search(": (.+?) ->", line).group(1) 
					n_relay = re.search("-> (.+?) ", line).group(1) 
				except:
					print "Could not find ip addresses for either p_relay or n_relay"

				if p_relay in circuit_dict[circ_id] and n_relay in circuit_dict[circ_id]:
					# find the relay id
					try:
						relay_id = re.search("\[tor-message\] \[(.+?)-", line).group(1)
						relay_ip = ip_addr_dict[relay_id]
					except AttributeError:
						print "Could not find the relay name?????"
				
					if relay_ip in circuit_dict[circ_id]:
						# filter line
						filt_line = filter_log_message(line)
						old = print_dict[relay_ip]
						old.append(filt_line)
						print_dict[relay_ip] = old
				
					
'''
	Currently works for the case in which there is only one fileclient.
	Can be expanded later.
'''				
if __name__ == "__main__":		
	ip_addr_dict = get_ip_addresses()
	circuit_dict = get_circuit_info(ip_addr_dict)
	get_stream_messages(ip_addr_dict, circuit_dict)
