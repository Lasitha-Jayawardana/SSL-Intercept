#######Lasitha##########

## Enable Interface Forwarding
	
 
	sudo sysctl net.ipv4.ip_forward=1
	WANIF='eth0'
	LANIF='eth1'

	 
	echo 'Enabling IP Masquerading and other rules...'
	sudo iptables -t nat -A POSTROUTING -o $LANIF -j MASQUERADE
	sudo iptables -A FORWARD -i $LANIF -o $WANIF -m state --state RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -A FORWARD -i $WANIF -o $LANIF -j ACCEPT

	sudo iptables -t nat -A POSTROUTING -o $WANIF -j MASQUERADE
	sudo iptables -A FORWARD -i $WANIF -o $LANIF -m state --state RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -A FORWARD -i $LANIF -o $WANIF -j ACCEPT

	echo 'Done.'

## Enable port forwarding

	sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 7080
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 12443
	sudo iptables -t nat -A PREROUTING -p tcp --dport 587 -j REDIRECT --to-ports 12443
	sudo iptables -t nat -A PREROUTING -p tcp --dport 465 -j REDIRECT --to-ports 12443
	sudo iptables -t nat -A PREROUTING -p tcp --dport 993 -j REDIRECT --to-ports 12443
	sudo iptables -t nat -A PREROUTING -p tcp --dport 5222 -j REDIRECT --to-ports 7080
 
