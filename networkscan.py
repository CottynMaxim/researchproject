import nmap
import netmiko
import re
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NETBOX_URL = 'https://192.168.20.250/api/'
NETBOX_TOKEN = 'c8a9c819f3213930b1277c724deb6eedee85835c'
HEADERS = {
    'Content-Type': 'application/json',
    'Authorization': f'Token {NETBOX_TOKEN}'
}

def get_manufacturer_id(manufacturer_name):
    url = f'{NETBOX_URL}dcim/manufacturers/'
    params = {'name': manufacturer_name}
    response = requests.get(url, params=params, headers=HEADERS, verify=False)  # Disable SSL verification

    if response.status_code == 200:
        manufacturers = response.json()['results']
        if manufacturers:
            return manufacturers[0]['id']
    else:
        print(f'Failed to fetch data. Status code: {response.status_code}, Response: {response.text}')
    return None

def create_manufacturer(manufacturer_name):
    # Generate slug from manufacturer name
    manufacturer_slug = manufacturer_name.lower().replace(' ', '_')

    url = f'{NETBOX_URL}dcim/manufacturers/'
    data_to_create = {
        'name': manufacturer_name,
        'slug': manufacturer_slug
    }

    response = requests.post(url, json=data_to_create, headers=HEADERS, verify=False)  # Disable SSL verification

    if response.status_code == 201:
        print(f'Manufacturer {manufacturer_name} created successfully in NetBox!')
        return response.json()['id']
    else:
        print(f'Failed to create manufacturer. Status code: {response.status_code}, Response: {response.text}')
        return None

def get_device_type_id(device_type_name):
    url = f'{NETBOX_URL}dcim/device-types/'
    params = {'model': device_type_name}
    response = requests.get(url, params=params, headers=HEADERS, verify=False)  # Disable SSL verification

    if response.status_code == 200:
        device_types = response.json()['results']
        if device_types:
            return device_types[0]['id']
    else:
        print(f'Failed to fetch data. Status code: {response.status_code}, Response: {response.text}')
    return None

def get_device_role_id(role_name):
    url = f'{NETBOX_URL}dcim/device-roles/'
    params = {'name': role_name}
    response = requests.get(url, params=params, headers=HEADERS, verify=False)  # Disable SSL verification

    if response.status_code == 200:
        roles = response.json()['results']
        if roles:
            return roles[0]['id']
    else:
        print(f'Failed to fetch data. Status code: {response.status_code}, Response: {response.text}')
    return None

def get_platform_id(platform_name):
    url = f'{NETBOX_URL}dcim/platforms/'
    params = {'name': platform_name}
    response = requests.get(url, params=params, headers=HEADERS, verify=False)  # Disable SSL verification

    if response.status_code == 200:
        platforms = response.json()['results']
        if platforms:
            return platforms[0]['id']
    else:
        print(f'Failed to fetch data. Status code: {response.status_code}, Response: {response.text}')
    return None

def create_platform(platform_name):
    # Generate slug from platform name
    platform_slug = platform_name.lower().replace(' ', '_')

    url = f'{NETBOX_URL}dcim/platforms/'
    data_to_create = {
        'name': platform_name,
        'slug': platform_slug
    }

    response = requests.post(url, json=data_to_create, headers=HEADERS, verify=False)  # Disable SSL verification

    if response.status_code == 201:
        print(f'Platform {platform_name} created successfully in NetBox!')
        return response.json()['id']
    else:
        print(f'Failed to create platform. Status code: {response.status_code}, Response: {response.text}')
        return None

def get_ip_address_id(ip_address):
    url = f'{NETBOX_URL}ipam/ip-addresses/'
    params = {'address': ip_address}
    response = requests.get(url, params=params, headers=HEADERS, verify=False)  # Disable SSL verification

    if response.status_code == 200:
        ip_addresses = response.json()['results']
        if ip_addresses:
            return ip_addresses[0]['id']
    else:
        print(f'Failed to fetch data. Status code: {response.status_code}, Response: {response.text}')
    return None

def create_ip_address(device_type_name, manufacturer_name, ip_address):
    # Check if the manufacturer and device type exist, create if not
    manufacturer_id = get_manufacturer_id(manufacturer_name)
    if manufacturer_id is None:
        manufacturer_id = create_manufacturer(manufacturer_name)

    device_type_id = get_device_type_id(device_type_name)
    if device_type_id is None:
        device_type_id = create_device_type(device_type_name, manufacturer_name)

    # Continue creating the IP address
    url = f'{NETBOX_URL}ipam/ip-addresses/'
    data_to_create = {
        'address': ip_address,
        'status': 'active',
        'device': device_type_id
    }

    response = requests.post(url, json=data_to_create, headers=HEADERS, verify=False)  # Disable SSL verification

    if response.status_code == 201:
        print(f'IP address {ip_address} created successfully in NetBox!')
        return response.json()['id']
    else:
        print(f'Failed to create IP address. Status code: {response.status_code}, Response: {response.text}')
        return None

def create_device_type(device_type_name, manufacturer_name):
    # Check if the manufacturer exists, create if not
    manufacturer_id = get_manufacturer_id(manufacturer_name)
    if manufacturer_id is None:
        manufacturer_id = create_manufacturer(manufacturer_name)

    # Continue creating the device type
    url = f'{NETBOX_URL}dcim/device-types/'
    data_to_create = {
        'model': device_type_name,
        'manufacturer': manufacturer_id,
        'slug': device_type_name.lower().replace(' ', '_')
    }

    response = requests.post(url, json=data_to_create, headers=HEADERS, verify=False)  # Disable SSL verification

    if response.status_code == 201:
        print(f'Device type {device_type_name} created successfully in NetBox!')
        return response.json()['id']
    else:
        print(f'Failed to create device type. Status code: {response.status_code}, Response: {response.text}')
        return None

def create_device(device_name, device_type_name, manufacturer_name, role_name,platform):
    # Check if the manufacturer and device type exist, create if not
    manufacturer_id = get_manufacturer_id(manufacturer_name)
    if manufacturer_id is None:
        manufacturer_id = create_manufacturer(manufacturer_name)

    device_type_id = get_device_type_id(device_type_name)
    if device_type_id is None:
        device_type_id = create_device_type(device_type_name, manufacturer_name)

    # Create a site (assuming you have a default site with ID 1, adjust as needed)
    site_id = 1


    # Get the ID of the device role or create it if it doesn't exist
    role_id = get_device_role_id(role_name)
    if role_id is None:
        # Assuming you have a default role with ID 1, adjust as needed
        role_id = 1

    # Get the ID of the platform or create it if it doesn't exist
    platform_id = get_platform_id(platform)
    if platform_id is None:
        platform_id = create_platform(platform)

    # Continue creating the device
    url = f'{NETBOX_URL}dcim/devices/'
    data_to_create = {
        'name': device_name,
        'device_type': device_type_id,
        'manufacturer': manufacturer_id,
        'role': role_id,
        'site': site_id,
        'platform': platform_id,
    }

    response = requests.post(url, json=data_to_create, headers=HEADERS, verify=False)  # Disable SSL verification

    if response.status_code == 201:
        print(f'Device {device_name} created successfully in NetBox!')
        return response.json()['id']
    else:
        print(f'Failed to create device. Status code: {response.status_code}, Response: {response.text}')
        return None

def get_device_id(device_name):
    url = f"{NETBOX_URL}dcim/devices/?name={device_name}"
    headers = {"Authorization": f"Token {NETBOX_TOKEN}"}
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        device_data = response.json()
        if device_data['count'] > 0:
            return device_data['results'][0]['id']
    return None

def get_vlan(vlan):
    url = f"{NETBOX_URL}ipam/vlans/?name={vlan}"
    headers = {"Authorization": f"Token {NETBOX_TOKEN}"}
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        device_data = response.json()
        if device_data['count'] > 0:
            return True
    return False




def create_vlan(vlan):
    if get_vlan(vlan) == False:
        vlan_id = int(vlan.strip("Vlan"))
        print(vlan_id)
        url = f"{NETBOX_URL}ipam/vlans/"
        data_to_create = {
            "vid": f"{vlan_id}",
            "name": vlan
        }
        response = requests.post(url, json=data_to_create, headers=HEADERS, verify=False)

        if response.status_code == 201:
            print(f"VLAN {vlan} created successfully.")
        else:
            print(f"Failed to create VLAN. Status code: {response.status_code}, Response: {response.text}")
    else:
        print(f"{vlan} already exists")


def create_interface(device,interface):
    url = f"{NETBOX_URL}dcim/interfaces/?device={device}"
    headers = {"Authorization": f"Token {NETBOX_TOKEN}"}
    data_to_create = {
        'name': interface,
        'type': '100base-tx',
        'device': get_device_id(device),
        'enabled': True,
    }
    response = requests.post(url, json=data_to_create, headers=headers, verify=False)  # Disable SSL verification

    if response.status_code == 201:
        print(f'Interface {interface} created successfully in NetBox!')
        return response.json()['id']
    else:
        print(f'Failed to create interface. Status code: {response.status_code}, Response: {response.text}')
        return None

def determine_device_type(device_info):
    capabilities_match = re.search(r'Capabilities: (.+)', device_info)
    if capabilities_match:
        capabilities = capabilities_match.group(1)
        if 'Router' in capabilities:
            return 'Router'
        elif 'Switch' in capabilities:
            return 'Switch'
    return 'Unknown'

def parse_device_info(device_info):
    device_id_match = re.search(r'Device ID: (.+)', device_info)
    ip_address_match = re.search(r'IP address: (\d+\.\d+\.\d+\.\d+)', device_info)
    platform_match = re.search(r'Platform: (.+),', device_info)
    return {
        'Device ID': device_id_match.group(1).strip().split(".")[0],
        'IP Address': ip_address_match.group(1).strip(),
        'Platform': platform_match.group(1).strip(),
        'Type': determine_device_type(device_info),
    }

def get_interfaces(output):
    Line = 0
    lines = output.split('\n')
    interfaces_and_ips = {}
    for line in lines:
        if Line > 0:
            Line += 1
            columns = line.split()
            if len(columns) == 6:
                interface = columns[0]
                ip_address = columns[1]
                interfaces_and_ips[interface] = ip_address
        else:
            Line +=1
    return interfaces_and_ips


def get_neighbors(ip):
    print(f'Enter login for the device with IP {ip}')
    username = input("What is the username? [Say skip to skip CDP neighbor discovery] ")
    if username.lower() == "skip":return None
    password = input("What is the password? ")
    secret = input("What is the secret? ")

    net_connect = netmiko.ConnectHandler(
        device_type="cisco_ios",
        host=ip,
        username=username,
        password=password,
        secret=secret,
    )

    net_connect.enable()
    output = net_connect.send_command("show cdp neighbor detail")
    interfaces = net_connect.send_command("show ip int brief")
    hostname = net_connect.find_prompt()
    hostname = hostname[:-1]
    print(hostname)
    interfaces = get_interfaces(interfaces)
    device_sections = re.split(r'[-]{25,}', output)

    devices = []
    for device_section in device_sections:
        if device_section.strip():
            device_info = parse_device_info(device_section)
            devices.append(device_info)

    neighbor_ips = []
    for device_info in devices:
        print(f"Device ID: {device_info['Device ID']}, IP Address: {device_info['IP Address']}, Platform: {device_info['Platform']}, Type: {device_info['Type']}")
        create_device(device_info['Device ID'],device_info['Type'],device_info['Platform'].split(" ")[0],device_info['Type'],"Cisco_IOS")
        neighbor_ips.append(device_info["IP Address"])
    print(interfaces)
    for interface,ip_address in interfaces.items():
            if "Vlan" in str(interface):
                create_vlan(interface)
            else:
                create_interface(hostname,interface)            
    print(neighbor_ips)
    return neighbor_ips

def scan_network(ip_range):
    for ip in ip_range:
        print('Starting scan on IP %s' % ip)
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-O -sV -T 5')  # '-O' enables OS detection

        for host in nm.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : %s' % nm[host].state())

            if 'mac' in nm[host]['addresses']:
                print('MAC Address : %s' % nm[host]['addresses']['mac'])
                print('OS : %s' % nm[host]['osmatch'][0]['name'])
                print('Probability : %s' % nm[host]['osmatch'][0]['accuracy'])
                if nm[host]['vendor']:
                   print('Vendor : %s' % nm[host]['vendor'][nm[host]['addresses']['mac']])
                   if str(nm[host]['vendor'][nm[host]['addresses']['mac']]) == "Cisco Systems":
                    ips = get_neighbors(ip)
                    if ips != None: 
                        for ip in ips:
                            get_neighbors(ip)
                    else:
                        print("Discovery skipped")
                else:
                   print('No vendor detected')
            else:
                print('MAC Address : None')

            for proto in nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)

                lport = nm[host][proto].keys()
                lport = list(lport)
                lport.sort()

                for port in lport:
                    print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

if __name__ == "__main__":
    # Specify the IP range you want to scan (e.g., '192.168.1.1-254')
    network = '192.168.20'
    start_ip = 1
    end_ip = 254
    ip_range = [f'{network}.{i}' for i in range(start_ip, end_ip + 1)]
    scan_network(ip_range)
