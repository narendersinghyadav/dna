# dna
**Module Overview:**

This module will interact with Tor to get real time statistical and analytical information.

|-is_alive - check tor process is alive or killed
|-is_valid_ipv4_address-check for valid ip address
|-authenticate- cookie authentication of control port
|-get_version- get version of tor 
|-get_pid- find pid of tor service
|-get_info- get information like version,exit policy,network status etc
|-set_conf- change the value of one or more configurable variable
|-reset_conf-set the configurable variable to default values
|-get_conf- Request the value of zero or more configuration variable
|-get_ports- retreive informations about listeners of different ports
|-get_network_statuses- Router status info (v3 directory style) for all ORs.
|-get_exit_policy-The default exit policy lines that Tor will *append* to the ExitPolicy config option.
|-prt_check-check validity of ports
|-can_exit_to- check whether one can exit through a particular port
|-get_circuit- get information about circuits present for use
|-port_usage-Usage of particular port
|-get_info_relay- retrieve information from database about a particular relay
|-status-tell status of a circuit BUILT or not
|-build_flag- build flag on circuit and relays
|-path- return path of circuit
|-created- circuit created info
|-signal-signal control port like NEWNYM,RELOAD etc
|-get_fingerprint-the contents of the fingerprint file that Tor writes as a relay, or a 551 if we're not a relay currently.
!-get_network_status-network status of a relay with given fingerprint
