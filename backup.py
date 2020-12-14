#!/usr/bin/env python3
import ipaddress
import os
import subprocess
import paramiko
from scp import SCPClient
import scp
import socket
import time
import logging
import threading
import queue
import sys
import contextlib


def get_vendor(host, snmp_version='1', snmp_community='public', snmp_attr='iso.3.6.1.2.1.1.1.0'):
    """
    get SNMPv2-MIB::sysDescr.0 from devices,
    MT
    SNMPv2-MIB::sysDescr.0 = STRING: RouterOS RB2011LS
    D-Link
    SNMPv2-MIB::sysDescr.0 = STRING: DES-3526 Fast-Ethernet Switch
    SNMPv2-MIB::sysDescr.0 = STRING: D-Link DES-1228/ME Metro Ethernet Switch
    UBNT
    SNMPv2-MIB::sysDescr.0 = STRING: Linux 2.6.32.54 #1 Tue May 28 17:56:11 EEST 2013 mip
    and
    iso.3.6.1.2.1.1.9.1.3.5 = STRING: "Ubiquiti Networks MIB module "
    """
    # TODO: need more detailed definition fro equipment
    with open(os.devnull, 'w') as f:
        try:
            snmp_req_sys_desc = 'snmpget -v{} -c {} {} {}'.format(snmp_version,
                                                                snmp_community,
                                                                host,
                                                                snmp_attr,
                                                                )
            # lst_snmp_dev_desc = snmp_req_sys_desc.split()
            output = subprocess.Popen(snmp_req_sys_desc.split(),
                                      stdout=subprocess.PIPE,
                                      stderr=f).communicate()[0].decode('utf-8').lower()
        except subprocess.CalledProcessError:
            return 'Timeout: No Response from ' + host

        if 'routeros' in output:
            return 'mikrotik'
        elif 'linux' in output:
            return 'ubiquiti'
        elif 'dgs' or 'des' in output:
            return 'dlink'
        elif 'rb260' in output:
            logging.info('{} equipment with swos'.format(host))
            return 'swos'


# backup for MT routers
def backup_mt_cfg(host):
    user, passwords, mt_port = config.secrets('mikrotik')
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # try just different pass's. Port, login and other shit maybe wrong
    # TODO: rework for communicate with DataBase
    for password in passwords:
        for port in mt_port:
            try:
                client.connect(hostname=host, username=user, password=password, port=port, look_for_keys=False)
                stdin, stdout, stderr = client.exec_command('system backup save name=' + host + '\n')
                # need to wait, when saving finished!
                # stdout.read () returned string in byte-mode
                if 'Configuration backup saved' in stdout.read().decode('utf-8'):
                    scpclient = SCPClient(client.get_transport())
                    scpclient.get(host + '.backup', path_backup + host + '.backup')
                    client.close()
                    logging.info(host + ' mt config saved')
                else:
                    client.close()
                    logging.warning(host + ' unsuccess. config not saved')
            except socket.timeout:
                logging.error(host + " unsuccess. SSH channel timeout exceeded.")
            # wrong pass/login
            except paramiko.AuthenticationException:
                if password == passwords[-1]:
                    logging.warning(host + ' unsuccess. incorrect login/pass pair!')
            except scp.SCPException:
                logging.error(host + ' unsuccess. SCP exception')
            except paramiko.ssh_exception.NoValidConnectionsError:
                port22 = ' NoValidConnectionsError, port 22'
            break
                # return host + ' unsuccess. NoValidConnectionsError'


# backup for ubnt devices
def backup_ubnt_cfg(host):
    user, passwords, ports = config.secrets('ubiquiti')
    # client = scp.Client(host=host, user=user, password=password)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for password in passwords:
        for port in ports:
            try:
                client.connect(hostname=host, username=user, password=password, port=port, look_for_keys=False)
                scpclient = SCPClient(client.get_transport())
                scpclient.get('/tmp/system.cfg', path_backup + host + '.cfg')
                client.close()
                logging.info(host + ' success. ubnt config saved')
            except socket.timeout:
                # smth wrong with ssh
                logging.error(host + ' unsuccess. SSH channel timeout exceeded.')
            # wrong auth
            except paramiko.AuthenticationException:
                # if last pass in, then no one pass was correct
                if password == passwords[-1]:
                    logging.warning(host + ' unsuccess. all PASS wrong!')
            # paramiko.ssh_exception.SSHException : Error reading SSH protocol banner
            # хост пингуется, а во время работы транспорта отваливается.
            except paramiko.ssh_exception.SSHException as e:
                logging.error('{} paramiko.ssh_exception.SSHException: {}'.format(host, e))
            except scp.SCPException:
                logging.error(host + ' unsuccess. SCP exception')
            except paramiko.ssh_exception.NoValidConnectionsError as e:
                logging.error('{} {}'.format(host, e))
                port22 = ' NoValidConnectionsError, port 22'
            return



# choose backup function by vendor
def backup(host):
    vendor = get_vendor(host)
    if vendor == 'mikrotik':
        backup_mt_cfg(host)
    elif vendor == 'ubiquiti':
        backup_ubnt_cfg(host)
    elif vendor == 'dlink':
        # TODO: make function for dlink backup
        logging.warning(host + 'Dlink. Configuration not saved.')
    elif vendor == 'swos':
        logging.warning('Mikrotik with SWoS. Have to save backup manualy.')

    logging.warning(host + 'Unknown equipment vendor.')


# один поток
def _thread(que):
    while True:
        # take host from queue
        host = que.get()
        if host is None:
            return
        # TODO: rework for crossplatform
        host_up = True if os.system("ping -c 1 " + host + ' > /dev/null') == 0 else False
        if host_up:
            backup(host)
        else:
            logging.warning('No Response from', host)
        que.task_done()


# основная функция
def main():
    # засекаем время
    start_time = time.time()
    logging.info('start backup')
    # количество потоков
    num_worker_threads = 25
    # очередь
    que = queue.Queue()
    # список потоков
    threads = []
    for _ in range(num_worker_threads):
        # создаём поток
        thread = threading.Thread(target=_thread, args=(que,))
        thread.start()
        threads.append(thread)

    for network in networks:
        for address in network:
            que.put(str(address))
    que.join()
    for _ in range(num_worker_threads):
        que.put(None)
    end_time = time.time()
    elapsed_time = end_time - start_time
    logging.info('elapsed time {}'.format(str(elapsed_time)))
    logging.info('backup configuration script finished')


if __name__ == '__main__':
    # change work directory to directory with script file
    # config file 'config.py' by default should be in the same dir with script
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    import config

    networks, path_backup, snmp_community, snmp_version = config.backup_conf()

    # logging configuration
    filename = time.ctime().split()[-1] + '_' + time.ctime().split()[1] + '_' + time.ctime().split()[2] + '_backaup_script.log'
    logging.basicConfig(
        filename=os.path.join(path_backup, filename),
        level=logging.ERROR,
        # format="%(asctime)s [%(name)s] [%(levelname)s]: %(message)s"
        format="%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s"
        )

    main()
