#!/usr/bin/python3

""" netcheck.py : Review relevant information about network interfaces and perform connectivity tests """

__author__     = 'Brent Elliott'
__email__      = 'brent.j.elliott@intel.com'
__license__    = 'GPL'
__version__    = '0.2.4'
__status__     = 'Development'
__copyright__  = 'Copyright 2023, Intel Corporation'
__github__     = 'https://www.github.com/brent-elliott/netcheck/'

import argparse
import json
import os
import re
import subprocess
import tempfile


#------------------------------------------------------------------------------------------------------------------------------------------
# main - primary netcheck implementation
#------------------------------------------------------------------------------------------------------------------------------------------
def main():

    #--------------------------------------------------------------------------------------------------------------------------------------

    # Parse command-line parameters
    parser = argparse.ArgumentParser(
                description='Review relevant information about network interfaces and perform connectivity tests',
                epilog='For more details, see ' + __github__,
                allow_abbrev=True)
    oper_group = parser.add_argument_group('Operational Parameters')
    filt_group = parser.add_argument_group('Formatting and Filtering')
    disp_group = parser.add_argument_group('Display Tables')

    oper_group.add_argument('-t', '--test',        action='store_true', help='Perform connectivity tests')
    oper_group.add_argument('-j', '--json',        action='store_true', help='Export all information in JSON format')
    oper_group.add_argument('-v', '--version',     action='store_true', help='Display version information')

    filt_group.add_argument('-u', '--up',          action='store_true', help='Only report interfaces that are UP')
    filt_group.add_argument('-s', '--summary',     action='store_true', help='Print shorter summary of interfaces and VLANs')
    filt_group.add_argument('-b', '--barebones',   action='store_true', help='Barebones (simplified) table formatting')

    disp_group.add_argument('-a', '--all',         action='store_true', help='Display all tables')
    disp_group.add_argument('-c', '--clear',       action='store_true', help='Clear the console before displaying tables')
    disp_group.add_argument('-I', '--interfaces',  action='store_true', help='Display interfaces table')
    disp_group.add_argument('-V', '--vlans',       action='store_true', help='Display vlans table')
    disp_group.add_argument('-D', '--dns',         action='store_true', help='Display dns table')
    disp_group.add_argument('-R', '--routes',      action='store_true', help='Display routes table')
    disp_group.add_argument('-P', '--pcie',        action='store_true', help='Display PCIe table')


    args = parser.parse_args()

    # Populate tables summarizing network interfaces
    itable = []     # interfaces
    vtable = []     # vlans
    ptable = []     # pcie devices
    rtable = []     # route table
    dtable = []     # dns table
    ttable = []     # connectivity tests table

    # Clear screen
    if args.clear:
        os.system('clear')

    # Show version information and exit
    if args.version:
        print(os.path.basename(__file__) + ' version ' + __version__)
        exit(0)

    # If test mode is selected, perform test but do not show normal output (ignoring -j, -u, -s flags)
    if args.test:
        tjson = test_connectivity(ttable, args.json)

        if args.json:
            print(tjson)
        else:
            print_table('Connectivity Tests', ttable, args.barebones)
        exit(0)

    # If no tables are selected with command-line parameters, default to interfaces and vlans,
    #   otherwise show exactly what is requested
    if not ( args.interfaces or args.vlans or args.dns or args.routes or args.pcie):
        args.interfaces = True
        args.vlans = True

    # Handle --all flag by setting all tables to true
    if args.all:
        args.interfaces = True
        args.vlans = True
        args.dns = True
        args.routes = True
        args.pcie = True

    #--------------------------------------------------------------------------------------------------------------------------------------

    # Get output of ip addr show command and create a JSON structure on which to hang additional useful information
    try:
        interfaces = json.loads(subprocess.run(['ip', '-detail', '-json', 'address', 'show'], capture_output=True).stdout.decode())
    except:
        print("\nERROR: Dependency 'ip' is missing or failing. Please troubleshoot the command 'ip address show' and retry.")
        exit(126)

    # Additional JSON entry to store human readable output
    human = json.loads('{}')

    #--------------------------------------------------------------------------------------------------------------------------------------

    # Parse through each network interface returned by ip addr show and collect additional information along the way
    for entry in interfaces:

        # Create empty default values for any missing required keys from ip addr show command
        for key in ['ifindex', 'ifname', 'link', 'address', 'operstate', 'ip']:
            if not key in entry:
                entry[key] = ''

        # Omit lo interface (not useful) and when the --up flag is used, also omit any interfaces that are not in the UP state
        if (entry['ifname'] != 'lo' and (not args.up or entry['operstate'] == 'UP')):

            # Create multiline listing for IPv4 addresses for human output
            human['ip'] = ''
            for address in entry['addr_info']:
                if address['family'] == 'inet':
                    if len(str(human['ip'])) > 0:
                        human['ip'] = human['ip'] + '\n'
                    human['ip'] = human['ip'] + address['local'] + '/' + str(address['prefixlen'])

            # Create multiline listing for altnames for human output
            human['altnames'] = ''
            if 'altnames' in entry:
                for name in entry['altnames']:
                    if len(str(human['altnames'])) > 0:
                        human['altnames'] += '\n'
                    human['altnames'] += name

            # Get ethtool driver output for interface
            try:
                eth_driver = subprocess.run(['ethtool', '-i', entry['ifname']], capture_output=True).stdout.decode()
            except:
                print("\nWARNING: Dependency 'ethtool' is missing or failing. Information will be missing from the output.")
                eth_driver = ''

            # Parse ethtool output and add to interfaces object
            for row in eth_driver.split('\n'):
                pair = row.split(': ')
                if len(pair) == 2:
                    entry[pair[0].lower().lstrip()] = pair[1].replace('\t', ',')

            # Get ethtool general output for interfaces
            try:
                eth_general = subprocess.run(['ethtool', entry['ifname']], capture_output=True).stdout.decode()
            except:
                print("\nWARNING: Dependency 'ethtool' is missing or failing. Information will be missing from the output.")
                eth_general = ''

            # Parse ethtool output and add to interfaces object
            for row in eth_general.split('\n'):
                pair = row.split(': ')
                if len(pair) == 2:
                    key = pair[0].lower().lstrip().rstrip().replace(' ', '-')

                    # Current script does not bother to parse less common multiline responses
                    reject_keys = [ 'supported-link-modes',
                                    'advertised-link-modes',
                                    'netlink-error',
                                    'current-message-level' ]
                    if not key in reject_keys:
                        entry[key] = pair[1].replace('\t', ',')

            # Create empty default values for any missing required keys from ethtool commands
            for key in ['driver', 'firmware-version', 'bus-info', 'speed', 'port', 'altnames']:
                if not key in entry:
                    entry[key] = ''

            # Remove leading characters in bus info for human output
            human['bus'] = ''
            if 'bus-info' in entry:
                human['bus'] = entry['bus-info'].replace('0000:', '')

                # Get lspci information for interface
                entry['device-name'] = ''
                if len(str(human['bus'])) > 0:
                    entry['device-name'] = subprocess.run(['lspci', '-s', human['bus']], capture_output=True).stdout.decode()
                    if ': ' in entry['device-name']:
                        entry['device-name'] = entry['device-name'].split(': ')[1].rstrip()
                    if len(str(entry['device-name'])) > 0:
                        ptable.append([ entry['ifindex'],
                                        entry['ifname'],
                                        human['bus'],
                                        entry['device-name'] ])


            # Clean up speed entries for human output - < 1 Gbps values will be unmodified
            human['speed'] = ''
            if   entry['speed'] == 'Unknown!':              human['speed'] = ''
            elif entry['speed'] == '1000Mb/s':              human['speed'] = '1 Gbps'
            elif entry['speed'] == '2500Mb/s':              human['speed'] = '2.5 Gbps'
            elif entry['speed'] == '5000Mb/s':              human['speed'] = '5 Gbps'
            elif entry['speed'] == '10000Mb/s':             human['speed'] = '10 Gbps'
            elif entry['speed'] == '25000Mb/s':             human['speed'] = '25 Gbps'
            elif entry['speed'] == '40000Mb/s':             human['speed'] = '40 Gbps'
            elif entry['speed'] == '50000Mb/s':             human['speed'] = '50 Gbps'
            elif entry['speed'] == '100000Mb/s':            human['speed'] = '100 Gbps'
            elif entry['speed'] == '200000Mb/s':            human['speed'] = '200 Gbps'
            elif entry['speed'] == '400000Mb/s':            human['speed'] = '400 Gbps'
            elif entry['speed'] == '800000Mb/s':            human['speed'] = '800 Gbps'

            # Clean up port entries for human output
            human['port'] = ''
            if   entry['port'] == 'None':                   human['port'] = ''
            elif entry['port'] == 'Twisted Pair':           human['port'] = 'BaseT'
            elif entry['port'] == 'Direct Attach Copper':   human['port'] = 'DAC'

            # Clean up missing information for openvswitch
            if entry['driver'] == 'openvswitch':
                entry['port'] = "Virtual"
                human['port'] = "Virtual"

                if entry['operstate'] == 'UNKNOWN':
                    entry['operstate'] = 'n/a'

            # Chop off firmware version beyond the first space for brevity in human output
            human['firmware'] = entry['firmware-version'].split(' ')[0]
            human['firmware'] = human['firmware'].replace(',', '')

            if len(str(entry['link'])) > 0:

                # Obtain VLAN ID (VID) for VLANs
                try:
                    entry['vlanid'] = entry['linkinfo']['info_data']['id']
                except:
                    entry['vlanid'] = ''

                # Add VLAN interface to vlan table
                vtable.append([ entry['ifindex'],
                                entry['ifname'],
                                entry['link'],
                                entry['vlanid'],
                                entry['address'],
                                entry['operstate'],
                                human['ip'] ])

            else:
                if args.summary:
                    # Add physical interface to interface table - summary mode
                    itable.append([ entry['ifindex'],
                                    entry['ifname'],
                                    entry['address'],
                                    entry['operstate'],
                                    human['ip'],
                                    entry['driver'],
                                    human['bus'],
                                    human['speed'],
                                    human['port'] ])

                else:
                    # Add physical interface to interface table - default mode
                    itable.append([ entry['ifindex'],
                                    entry['ifname'],
                                    entry['address'],
                                    entry['operstate'],
                                    human['ip'],
                                    entry['driver'],
                                    human['firmware'],
                                    human['bus'],
                                    human['speed'],
                                    human['port'],
                                    human['altnames'] ])

    #--------------------------------------------------------------------------------------------------------------------------------------

    # Get output of ip route command
    try:
        routes = json.loads(subprocess.run(['ip', '-detail', '-json', 'route'], capture_output=True).stdout.decode())
    except:
        print("\nWARNING: Dependency 'ip' is missing or failing. Please troubleshoot the command 'ip route' and retry.")
        routes = json.loads('{}')

    # Populate human readable route table
    for route in routes:
        # Create empty default values for any missing required keys from ethtool commands
        for key in ['dst', 'gateway', 'dev', 'protocol', 'metric']:
            if not key in route:
                route[key] = ''

        rtable.append([ route['dst'],
                        route['gateway'],
                        route['dev'],
                        route['protocol'],
                        route['metric'] ])

    #--------------------------------------------------------------------------------------------------------------------------------------

    # Get DNS Server information per interfaces

    dns = json.loads('{}')

    try:
        dnsinfo = subprocess.run(['resolvectl'], capture_output=True).stdout.decode()
    except:
        print("\nWARNING: Dependency 'resolvectl' is missing or failing. Please troubleshoot the command 'resolvectl' and retry.")
        dnsinfo = ''


    # resolvectl has different formatting in differnet versions
    #   this filter will converge to a format where fields are not split across multiple lines
    dnsfilter = ''
    for line in dnsinfo.split('\n'):

        # ignore blank lines
        if len(line) > 0:

            # treat lines with ': ' as a key value pair line
            if ': ' in line:
                dnsfilter += '\n' + line.lstrip().rstrip()
            else:
                # treat lines with a '(' as a line containing a device name
                if '(' in line:
                    dnsfilter += '\n' + line.lstrip().rstrip()
                # treat line containing Global as a special "device" name
                elif line == 'Global':
                    dnsfilter += '\n' + line.lstrip().rstrip()
                # treat all other lines as a continuation of the previous field - so omit the newline
                else:
                    dnsfilter += ' ' + line.lstrip().rstrip()

    # Parse ethtool output and add to interfaces object
    current_device = ''

    for line in dnsfilter.split('\n'):

        if not ':' in line:
            current_device = line
            if "(" in line:
                match = re.search('\(([\w0-0\.\-\_]+)\)', line)
                if len(match.groups()) >= 1:
                    current_device = match.group(1)
            if len(current_device) > 0:
                dns[current_device] = json.loads('{}')

        else:
            pair = line.split(': ')

            if len(pair) == 2:
                key = pair[0].lower().lstrip().rstrip().replace(' ', '-')

                # Current script does not bother to parse less common multiline responses
                reject_keys = [ ]
                if not key in reject_keys:
                    dns[current_device][key] = pair[1]

    # Create empty default values for any missing required keys from ethtool commands
    for device in dns:
        for key in ['current-dns-server', 'dns-servers', 'dns-domain']:
            if not key in dns[device]:
                dns[device][key] = ''

    # Populate human readable DNS table
    for device in dns:
        if len(device) > 0:
            # Only append entries where there is one or more columns of data available
            if ( len(str(dns[device]['current-dns-server'])) > 0 or
                 len(str(dns[device]['dns-servers']))        > 0 or
                 len(str(dns[device]['dns-domain']))         > 0 ):

                dtable.append([ device,
                                dns[device]['current-dns-server'],
                                dns[device]['dns-servers'].replace(' ', '\n'),
                                dns[device]['dns-domain'].replace(' ', '\n') ])

    #--------------------------------------------------------------------------------------------------------------------------------------

    # Output all results either as human readable or in JSON format per parameters
    if args.json:
        response = json.loads('{}')
        response['interfaces'] = interfaces
        response['routes'] = routes
        response['dns'] = dns
        print(json.dumps(response))

    else:
        # Sort tables
        if args.summary:
            itable.sort(key=lambda x:x[6])
        else:
            itable.sort(key=lambda x:x[7])

        vtable.sort(key=lambda x:x[1])
        vtable.sort(key=lambda x:x[2])
        ptable.sort(key=lambda x:x[2])

        # Add headers
        if args.summary:
            itable.insert(0,['ID', 'INTERFACE', 'MAC ADDRESS', 'STATE', 'IP ADDRESSES', 'DRIVER', 'BUS', 'SPEED', 'PORT'])
        else:
            itable.insert(0,['ID', 'INTERFACE', 'MAC ADDRESS', 'STATE', 'IP ADDRESSES', 'DRIVER', 'FIRMWARE', 'BUS', 'SPEED', 'PORT', 'ALTNAMES'])

        vtable.insert(0, ['ID', 'INTERFACE', 'LINK', 'VID', 'MAC ADDRESS', 'STATE', 'IP ADDRESSES'])
        ptable.insert(0, ['ID', 'INTERFACE', 'BUS', 'DESCRIPTION'])
        rtable.insert(0, ['DESTINATION', 'GATEWAY', 'INTERFACE', 'PROTOCOL', 'METRIC'])
        dtable.insert(0, ['INTERFACE', 'CURRENT SERVER', 'ALL SERVERS', 'DOMAINS'])

        # Print tables selected per command-line parameters
        if args.summary:
            format = 'outline'

        if args.interfaces:
            if len(itable) > 1:
                print_table('Physical Interfaces', itable, args.barebones)
            else:
                print('No network interfaces found.')

        if args.vlans:
            if len(vtable) > 1:
                print_table('VLAN Interfaces', vtable, args.barebones)
            else:
                print('No VLANs configured.')

        if args.dns:
            if len(dtable) > 1:
                print_table('DNS Server Table', dtable, args.barebones)
            else:
                print('No DNS entries found.')

        if args.routes:
            if len(rtable) > 1:
                print_table('Route Table', rtable, args.barebones)
            else:
                print('No routes found.')

        if args.pcie:
            if len(ptable) > 1:
                print_table('PCIe Device Details', ptable, args.barebones)
            else:
                print('No PCIe devices corresponding to network interfaces found.')



#------------------------------------------------------------------------------------------------------------------------------------------
# test_connectivity - Perform network connectivity tests (employed iwth -t or --test flags)
#
#   parameters
#     - ttable     - A 2D list to store the connectivity test results and supporting information
#------------------------------------------------------------------------------------------------------------------------------------------
def test_connectivity(ttable, suppress_output):

    # Perform connectivity tests
    ping1_pass = 'FAIL'
    ping1_value = 0
    ping2_pass = 'FAIL'
    ping2_value = 0
    wget_pass = 'FAIL'
    wget_value = ''
    nhop_pass = 'FAIL'
    nhop_value = ''
    nhop_gateway = ''
    throughput_pass = 'FAIL'
    throughput_value = ''

    # Test ping to public IP *without* DNS lookup required
    if not suppress_output: print('\r[ TESTING .     ] ', end='')
    try:
        ping1_test = subprocess.run(['ping', '-q', '-c', '5', '-i', '0.25', '-W', '0.5', '1.1.1.1'], capture_output=True)

        match = re.search('rtt.*= ([0-9\.]+)/([0-9\.]+)/([0-9\.]+)/([0-9\.]+) ms', ping1_test.stdout.decode().replace('\n', ' | '))
        ping1_value = 'unknown'
        if not match is None:
            if len(match.groups()) >= 3:
                ping1_value = match.group(2) + ' ms'

        if ping1_test.returncode == 0: ping1_pass = 'PASS'
    except:
        print("\nWARNING: Dependency 'ping' is missing or failing. Direct IP connectivity results will be missing.")

    # Test ping to public IP *with* DNS lookup required
    if not suppress_output: print('\r[ TESTING ..    ] ', end='')
    try:
        ping2_test = subprocess.run(['ping', '-q', '-c', '5', '-i', '0.25', '-W', '0.5', 'www.cloudflare.com'], capture_output=True)

        match = re.search('rtt.*= ([0-9\.]+)/([0-9\.]+)/([0-9\.]+)/([0-9\.]+) ms', ping2_test.stdout.decode().replace('\n', ' | '))
        ping2_value = 'unknown'
        if not match is None:
            if len(match.groups()) >= 2:
                ping2_value = match.group(2) + ' ms'

        if ping2_test.returncode == 0: ping2_pass = 'PASS'
    except:
        print("\nWARNING: Dependency 'ping' is missing or failing. Direct IP connectivity results will be missing.")

    # Test wget operation to public website - attempt to sense proxy usage (if properly configured)
    if not suppress_output: print('\r[ TESTING ...   ] ', end='')
    try:
        temporary_filepath = os.path.join(tempfile.gettempdir(), next(tempfile._get_candidate_names()))
        wget_test = subprocess.run(['wget', '-O', temporary_filepath, 'https://www.cloudflare.com/'], capture_output=True)
        os.remove(temporary_filepath)

        match = re.search('Connecting to ([\w\d\.\-]+)', wget_test.stderr.decode())
        connecting_url = 'unknown'
        if not match is None:
            if len(match.groups()) >= 1:
                connecting_url = match.group(1)
                if connecting_url == 'www.cloudflare.com':
                    wget_value = 'Direct - no proxy detected'
                else:
                    wget_value = 'Proxy via ' + connecting_url

        if wget_test.returncode == 0: wget_pass = 'PASS'
    except:
        print("\nWARNING: Dependency 'wget' is missing or failing. Web results will be missing.")

    # Ping the default gateway and extract latency, default gateway IP address and interface used to reach it
    if not suppress_output: print('\r[ TESTING ....  ] ', end='')
    try:
        # Lookup next hop IP to reach 1.1.1.1
        nhop_lookup = json.loads(subprocess.run(['ip', '--json', 'route', 'get', '1.1.1.1'], capture_output=True).stdout.decode())

        nhop_test = subprocess.run(['ping', '-q', '-c', '4', '-i', '0.25', '-W', '0.5', nhop_lookup[0]['gateway']], capture_output=True)
        match = re.search('rtt.*= ([0-9\.]+)/([0-9\.]+)/([0-9\.]+)/([0-9\.]+) ms', nhop_test.stdout.decode().replace('\n', ' | '))
        nhop_value = 'unknown'
        if not match is None:
            if len(match.groups()) >= 2:
                nhop_value = match.group(2) + ' ms'

        nhop_gateway = '(' + nhop_lookup[0]['gateway'] + ' via ' + nhop_lookup[0]['dev'] + ')'
        if nhop_test.returncode == 0: nhop_pass = 'PASS'
    except:
        print("\nWARNING: Dependency 'ip' or 'ping' is missing or failing. Next Hop ping results will be missing.")

    # Quick download throughput test
    if not suppress_output: print('\r[ TESTING ..... ] ', end='')
    if wget_pass == 'PASS':

        test_url = 'https://aka.azureedge.net/probe/test10mb.jpg'

        # Note that some URLS may be blocked on some networks

        # Azure CDN (Akamai)  - https://aka.azureedge.net/probe/test10mb.jpg
        # CacheFly CDN        - https://cloudharmony1.cachefly.net/probe/test10mb.jpg
        # Amazon CloudFront   - https://cloudharmony.com/probe/test10mb.jpg
        # Limelight CDN       - https://labtest-gartner.lldns.net/web-probe/test10mb.jpg
        # Cloudflare          - https://cloudflarecdn.cloudharmony.net/probe/test10mb.jpg
        # Azure CDN (Verizon) - https://ch.azureedge.net/probe/test10mb.jpg
        # Fastly CDN          - https://cloudharmony.global.ssl.fastly.net/probe/test10mb.jpg
        # Google Cloud CDN    - https://cdn-google.cloudharmony.net/probe/test10mb.jpg

        temporary_filepath = os.path.join(tempfile.gettempdir(), next(tempfile._get_candidate_names()))
        throughput_test = subprocess.run([ 'wget', '--report-speed=bits', '--compression=none',
                                           '--no-check-certificate', '-O', temporary_filepath, test_url ], capture_output=True)
        os.remove(temporary_filepath)
        match = re.search('\(([\w\d\.\/ ]+)\) - ', throughput_test.stderr.decode())
        if not match is None:
            if len(match.groups()) >= 1:
                throughput_value = str(match.group(1)).replace('/','p')

        if throughput_test.returncode == 0: throughput_pass = 'PASS'

    if not suppress_output: print('\r', end='')

    ttable.append(['Test Description', 'Result', 'Details'])
    ttable.append(['Ping to Default Gateway', nhop_pass, nhop_gateway + " " + nhop_value])
    ttable.append(['Ping to Internet without DNS Lookup', ping1_pass, ping1_value])
    ttable.append(['Ping to Internet with DNS Lookup', ping2_pass, ping2_value])
    ttable.append(['Webpage Download', wget_pass, wget_value])
    ttable.append(['Brief Downlink Throughput', throughput_pass, throughput_value])

    # Create a list to store the test results
    test_results = []

    # Add test results to the list
    test_results.append({"test": "ping-gw", "result": nhop_pass, "rtt": nhop_value, "gateway": nhop_gateway})
    test_results.append({"test": "ping-internet", "result": ping1_pass, "rtt": ping1_value})
    test_results.append({"test": "ping-internet-with-dns", "result": ping2_pass, "rtt": ping2_value})
    test_results.append({"test": "webpage-load", "result": wget_pass, "details": wget_value})
    test_results.append({"test": "downlink-throughput", "result": throughput_pass, "rate": throughput_value})

    # Convert the test results to a JSON string
    return(json.dumps(test_results))



#------------------------------------------------------------------------------------------------------------------------------------------
# print_table - Print a table with the specified table and values - assumes the first row is the column headers
#
#   parameters
#     - title     - A short string to be displayed above the table
#     - table     - A 2D list containing the rows and columns of data inlcuding headers in the first row
#     - barebones - Boolean flag determining whether to use barebones (simplified) formatting
#------------------------------------------------------------------------------------------------------------------------------------------
def print_table(title, table, barebones):

    # Notes:
    # - Current implementation does not support newlines in the column headers or the table header
    # - Current implementation does not handle table header longer than the sum of columns below
    # - Current implementation does not support stretching out table (width or height)

    # Do not print tables with zero rows or columns
    if len(table) == 0:
        return
    elif len(table[0]) == 0:
        return

    # Determine table dimensions
    num_rows = len(table)
    num_cols = len(table[0])
    col_widths = [0] * num_cols
    row_heights = [1] * num_rows

    print_gridlines = True

    # Find the maximum size of each column (headers and data)
    for row in range(num_rows):
        for col in range(num_cols):
            for line in str(table[row][col]).split('\n'):
                this_width = len(line)
                if this_width > col_widths[col]:
                    col_widths[col] = this_width
            this_height = len(str(table[row][col]).split("\n"))
            if this_height > row_heights[row]:
                row_heights[row] = this_height

    total_width = 0
    for col in range(num_cols):
        total_width += col_widths[col] + 3

    # Create top bar for table title
    if not barebones:
        print('\033[1;30m', end='')
        for col in range(num_cols):
            if col == 0:
                print('╭' + '─' * (col_widths[col] + 2), end='')
            else:
                print('─' * (col_widths[col] + 3), end='')
        print('╮')

    # Create table title
    if not barebones:
        print('│ \033[0m\033[0;30;47m' + title.center(total_width - 3) + '\033[0m\033[1;30m │')
    else:
        print('### ' + title + ' ###')

    # Create top bar for column headers
    if not barebones:
        for col in range(num_cols):
            if col == 0:
                print('├' + '─' * (col_widths[col] + 2), end='')
            else:
                print('┬' + '─' * (col_widths[col] + 2), end='')
        print('┤')

    # Print headers
    if not barebones:
        for col in range(num_cols):
            print('│\033[0m\033[1m' + str(table[0][col]).center(col_widths[col]+2) + '\033[0m\033[1;30m', end='')
        print('│')
    else:
        for col in range(num_cols):
            print(str(table[0][col]).center(col_widths[col]+2), end='')
        print()


    # Create bottom bar for column headers
    if not barebones:
        for col in range(num_cols):
            if col == 0:
                print('├' + '─' * (col_widths[col] + 2), end='')
            else:
                print('┼' + '─' * (col_widths[col] + 2), end='')
        print('┤')

    # Print each row in the table
    if not barebones:
        for row in range(1,num_rows):
            for line in range(row_heights[row]):
                for col in range(num_cols):

                    split_text = str(table[row][col]).split("\n")
                    if len(split_text) > line:
                        text = split_text[line]
                    else:
                        text = ""

                    print('\033[0m\033[1;30m│\033[0m\033[1m', end='')

                    if text == "UP":
                        print('\033[92m' + text.rjust(col_widths[col] + 1) + '\033[0m\033[1m', end='')
                    elif text == "DOWN":
                        print('\033[31m' + text.rjust(col_widths[col] + 1) + '\033[0m\033[1m', end='')
                    elif text == "LOWERLAYERDOWN":
                        print('\033[31m' + text.rjust(col_widths[col] + 1) + '\033[0m\033[1m', end='')
                    else:
                        print('\033[0m' + text.rjust(col_widths[col] + 1) + '\033[1m', end='')
                    print(' ', end='')
                print('\033[0m\033[1;30m│')

            if print_gridlines and row < num_rows - 1:
                # Create bottom bar for column headers
                for col in range(num_cols):
                    if col == 0:
                        print('├\033[1;30m' + '─' * (col_widths[col] + 2), end='')
                    else:
                        print('┼\033[1;30m' + '─' * (col_widths[col] + 2), end='')
                print('\033[0m\033[1;30m┤')
    else:
        for row in range(1,num_rows):
            for line in range(row_heights[row]):
                for col in range(num_cols):

                    split_text = str(table[row][col]).split("\n")
                    if len(split_text) > line:
                        text = split_text[line]
                    else:
                        text = ""

                    print(text.rjust(col_widths[col] + 1) + ' ', end='')
                print()

    # Create bottom bar for column headers
    if not barebones:
        for col in range(num_cols):
            if col == 0:
                print('╰' + '─' * (col_widths[col] + 2), end='')
            else:
                print('┴' + '─' * (col_widths[col] + 2), end='')
        print('╯\033[0m')
    else:
        print()



#------------------------------------------------------------------------------------------------------------------------------------------

# Execute main function
if __name__ == '__main__':
    main()

#------------------------------------------------------------------------------------------------------------------------------------------
