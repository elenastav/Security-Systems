Assignment 5 

Kleinta Giaoupi 20190300132 & Elena Stavropoulou 2019030070

How to run:

sudo ./adblock.sh -option

-domains: Configure adblock rules based on the domain names of “domainNames.txt” file.
-ips: Configure adblock rules based on the IP addresses of “IPAddresses.txt”.
-save: Save rules to “adblockRules” file (this file does not have a filename extension).
-load: Load rules from “adblockRules” file (this file does not have a filename extension).
-reset: Reset rules to default settings (i.e. accept all).
-list: List current rules.
-help: Display help and exit.

Code Description:

-domains: Reads domain names from the specified file (domainNames.txt) and obtains corresponding IPv4 and IPv6 addresses using dig. Appends these addresses to the IPAddresses.txt file.
-ips: Reads IP addresses from the specified file (IPAddresses.txt) and adds corresponding rules to reject incoming traffic using iptables for IPv4 and ip6tables for IPv6.
-save: Uses iptables-save and ip6tables-save to capture the current firewall rules and appends them to the specified file (adblockRules).
-load: Uses iptables-restore to load IPv4 rules and ip6tables-restore to load IPv6 rules from the specified file (adblockRules).
-reset: Flushes existing rules using iptables -F for IPv4 and ip6tables -F for IPv6, effectively accepting all incoming traffic.
-list: Displays the current IPv4 and IPv6 rules using iptables -L and ip6tables -L.
-help: Prints a help message explaining the purpose of the script and provides a summary of available options.

Question:

After configuring the adblock rules, test your script by visiting your favorite
websites without any other adblocking mechanism (e.g., adblock browser
extensions). Can you see ads? Do they load? Some ads persist, why?

We visited random sites and some of the domains from the list and we observed that some ads persisted. The reasons for that could be:
-Several ads are transmitted using a secure connection over HTTPS, so adblockers can't block them.
-Several ads are loaded dynamically using JavaScript or other dynamic loading techniques.
-Several ads aren't blocked because they come from a trusted source, so the adblock rules don't apply to them.