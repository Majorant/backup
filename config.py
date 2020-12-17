
import os.path
from ipaddress import ip_network
import yaml


def backup_conf():
    with open(os.path.join(os.path.dirname(__file__), 'backup.yaml'), 'r') as f:
        conf = yaml.load(f, Loader=yaml.BaseLoader)
        networks = [ip_network(i) for i in conf['ipaddresses']]
        path = conf['path_backup']
        community = conf['snmp_community']
        version = conf['snmp_version']
    return networks, path, community, version


def secrets(vendor):
    with open(os.path.join(os.path.dirname(__file__), 'devices.yaml'), 'r') as f:
        conf = yaml.load(f, Loader=yaml.BaseLoader)
        equip = conf[vendor]
        return equip['user'], equip['secrets'], equip['ports']


if __name__ == '__main__':
    backup_conf()
    secrets('mikrotik')
