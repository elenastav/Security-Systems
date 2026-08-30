#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Configure adblock rules based on the domain names of $domainNames file.
        while read domain; do
		# IPv4
        ipsv4=$(dig +short $domain A)
        if [ "$ipsv4" != ";; connection timed out; no servers could be reached" ]; then
            echo "$ipsv4" | while read ip; do
                if [ -n "$ip" ]; then
                    echo "$ip" >> $IPAddresses
                fi
            done
        fi
        # IPv6
        ipsv6=$(dig +short $domain AAAA)
        if [ "$ipsv6" != ";; connection timed out; no servers could be reached" ]; then
            echo "$ipsv6" | while read ip; do
               if [ -n "$ip" ]; then
                    echo "$ip" >> $IPAddresses
                fi
            done
        fi

    done < $domainNames
        true
            
    elif [ "$1" = "-ips"  ]; then
        # Configure adblock rules based on the IP addresses of $IPAddresses file.
        while read -r ip; do
          if [[ "$ip" =~ ":" ]]; then
            # IPv6 
            ip6tables -A INPUT -s "$ip" -j REJECT
          else
            # IPv4 
            iptables -A INPUT -s "$ip" -j REJECT
          fi
        done < "IPAddresses.txt"
        true
        
		
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        iptables-save  > $adblockRules
		ip6tables-save  >> $adblockRules
        true
        

    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        sed '/COMMIT/q' $adblockRules | iptables-restore
        sed -n "/COMMIT/,$ p" $adblockRules | sed -n "2,$ p" | ip6tables-restore
        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        ip6tables -F
        iptables -F
        true

        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
        ip6tables -L
        iptables -L        
        true
        
		
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0
