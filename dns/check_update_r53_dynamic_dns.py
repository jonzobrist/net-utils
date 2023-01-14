#!/usr/bin/env python3
# What: check_update_r53_dynamic_dns.py
# Why:  Check if the public IP has changed, and if so, update the DNS record in Route53
# Usage: ./check_update_r53_dynamic_dns.py -c /path/to/config.json || ./check_update_r53_dynamic_dns.py -n myhostname -z myzoneid  
# From crontab:
# ./check_update_r53_dynamic_dns.py
# */5 * * * * ${HOME}/bin/check_update_r53_dynamic_dns.py >> ${HOME}/logs/dns-external.log
# ||
# */5 * * * * ${HOME}/bin/check_update_r53_dynamic_dns.py -n myhostname -z myzoneid >> ${HOME}/logs/dns-external.log
# Assumes you have AWS credentials/config setup already (see http://boto.cloudhackers.com/en/latest/boto_config_tut.html)
# you can start by just running it with -n and -z, and it will save to a config file (pass in custom path with -c)
# Once the config file exists, you can run it without the -n and -z

import re
import json
import requests
import argparse
import datetime
import boto
from time import sleep
from socket import gethostbyname
from pathlib import Path

DEFAULT_CONFIG_FILE = Path.home().joinpath('etc/dns-config.json')
DEFAULT_TTL = 60
DEFAULT_RECORD_TYPE = 'A'
DEFAULT_HTTPBIN_URL = 'https://www.dangfast.com/ip' # this is my website, running httpbin, which returns the IP address of the client at '/ip'. No guarantee it'll be up, check and feel free to use if it is.
# HTTPBin lives at https://github.com/postmanlabs/httpbin
DEFAULT_HOSTNAME = False
DEFAULT_HOSTED_ZONE = False

def DEBUG(message):
    if 'DEBUG' in locals():
        print(message)
    print(message)

def is_ipv4(ip):
    ip_re = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    if ip_re.match(ip):
        return True
    else:
        return False

def is_valid_hostname(hostname):
    if len(hostname) <= 255 and type(hostname == str):
        valid_hostname = re.compile(r"^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?$")
        if valid_hostname.match(hostname):
            return True
    return False

def get_ip_dns(hostname):
    # I don't use this because hosts often don't have a FQDN, or the external one is different
    return gethostbyname(hostname)

def get_ip_httpbin(url=DEFAULT_HTTPBIN_URL):
    # We expect a httpbin json object back like:
    # {
    #  "origin": "1.2.3.4"
    #      }
    pagedata = requests.get(url)
    my_ip = res_json = json.loads(pagedata.text)
    return(my_ip['origin'])

def load_config(config_file=DEFAULT_CONFIG_FILE):
    # Given a config file, load & check it, and return a dict
    # config_file = Path.home().joinpath('etc/lastpublicip')
    if type(config_file) != 'pathlib.PosixPath':
        full_path = Path(config_file)
    else:
        full_path = config_file
    if full_path.exists():
        my_config = json.load(open(full_path))
        if check_config(my_config):
            return my_config
        else:
            return False
    else:
        DEBUG(f'config file {config_file} does not exist')
        return False

def write_config(my_config, config_file=DEFAULT_CONFIG_FILE):
    # Given a config file, load & check it, and return a dict
    # config_file = Path.home().joinpath('etc/lastpublicip')
    dt = datetime.datetime.now()
    updatetime = dt.timestamp()
    my_config['updated'] = updatetime
    if check_config(my_config):
        with open(config_file, 'w') as myfh:
            json.dump(my_config, myfh)
        return True
    else:
        return False

# def check_config(hosted_zone, hostname, my_config=DEFAULT_CONFIG_FILE, ttl=DEFAULT_TTL, record_type=DEFAULT_RECORD_TYPE):
def check_config(my_config):
    # Given a config dict, check to make sure it has the right keys
    # and return True if it does, otherwise return False
    if 'hostname' not in my_config.keys():
        my_config['hostname'] = hostname
    if 'ttl' not in my_config.keys():
        my_config['ttl'] = ttl
    if 'record_type' not in my_config.keys():
        my_config['record_type'] = record_type
    if 'hosted_zone' not in my_config.keys():
        my_config['hosted_zone'] = hosted_zone
    if 'hostname' in my_config and 'ttl' in my_config and 'record_type' in my_config and 'hosted_zone' in my_config:
        return my_config
    else:
        return False

# Moved these defaults to argparse, leaving here for future library use
def generate_new_config(hostname, hosted_zone, config_file=DEFAULT_CONFIG_FILE, record_type=DEFAULT_RECORD_TYPE, ttl=DEFAULT_TTL):
    # Given a hostname, and optioanl non-default config file, create a new file and save it
    # Let's put the config things into a dict
    # and to return as a json object
    my_config = dict()
    if is_valid_hostname(hostname):
        my_config['hostname'] = hostname
    else:
        DEBUG('Config passed in was not a valid hostname')
    if hosted_zone and type(hosted_zone) == str:
        my_config['hosted_zone'] = hosted_zone
    else:
        DEBUG('Hosted zone missing or is not a valid string')
    my_config['record_type'] = record_type
    my_config['ttl'] = ttl
    if check_config(my_config):
        return my_config
    else:
        return False

def upsert_record(r53, zone, name, record, record_type, ttl=60, wait=False):
    print("Inserting record {}[{}] -> {}; TTL={}".format(name, record_type, record, ttl))
    recordset = boto.route53.record.ResourceRecordSets(connection=r53, hosted_zone_id=zone.get('Id').split('/')[-1])
    recordset.add_change_record('UPSERT', boto.route53.record.Record(
        name=name,
        type=record_type,
        resource_records=[record],
        ttl=ttl
    ))
    changeset = recordset.commit()

    change_id = changeset['ChangeResourceRecordSetsResponse']['ChangeInfo']['Id'].split('/')[-1]

    while wait:
        status = r53.get_change(change_id)['GetChangeResponse']['ChangeInfo']['Status']
        if status == 'INSYNC':
            break

        sleep(10)

def get_r53_zone(domain_name, r53=False):
    if not r53:
        r53 = boto.connect_route53()
    return r53.get_hosted_zone_by_name(domain_name)

# def upsert_record(hosted_zone, hostname, my_ip, record_type, ttl=60, wait=False, r53=False):
def upsert_record(my_config, wait=False, r53=False):
    if not r53:
        r53 = boto.route53.connection.Route53Connection()
    hostname = my_config['hostname']
    zone = my_config['hosted_zone']
    record_type = my_config['record_type']
    ttl = my_config['ttl']
    my_ip = my_config['my_ip']
    DEBUG("Inserting record {}[{}] -> {}; TTL={}".format(hostname, record_type, my_ip, ttl))
    recordset = boto.route53.record.ResourceRecordSets(connection=r53, hosted_zone_id=hosted_zone)
    recordset.add_change_record('UPSERT', boto.route53.record.Record(
        name=hostname,
        type=record_type,
        resource_records=[my_ip],
        ttl=ttl
    ))
    changeset = recordset.commit()
    change_id = changeset['ChangeResourceRecordSetsResponse']['ChangeInfo']['Id'].split('/')[-1]
    while wait:
        status = r53.get_change(change_id)['GetChangeResponse']['ChangeInfo']['Status']
        if status == 'INSYNC':
            break
        sleep(5)


if __name__ == '__main__':
    # for our main function, we'll create an argparser, have arguments for hostname, hosted_zone, config_file, record_type, ttl
    parser = argparse.ArgumentParser(description='Update Route53 with your public IP')
    parser.add_argument('-c', '--config', dest='config_file', type=str, help='Config file to use', default=DEFAULT_CONFIG_FILE)
    parser.add_argument('-n', '--hostname', dest='hostname', help='Hostname to update', default=DEFAULT_HOSTNAME)
    parser.add_argument('-z', '--hosted_zone', dest='hosted_zone', help='Hosted zone to update', default=DEFAULT_HOSTED_ZONE)
    parser.add_argument('-y', '--record_type', dest='record_type', type=str, help='Record type to update', default=DEFAULT_RECORD_TYPE)
    parser.add_argument('-t', '--ttl', dest='ttl', type=int, help='Record type to update', default=DEFAULT_TTL)
    args = parser.parse_args()
    try:
        my_config = load_config(args.config_file)
    except:
        if args.hostname and args.hosted_zone:
            my_config = generate_new_config(args.hostname, args.hosted_zone, args.config_file, args.record_type, args.ttl)
            write_config(my_config, args.config_file)
        else:
            print("ERROR: No config file found, and no hostname or hosted zone provided, exiting")
            exit(1)
    # At this point we should have a working config with a hostname and hosted zone from args, or from the config file
    # Time to get the IP from httpbin, and the IP from DNS
    my_ip = get_ip_httpbin() # Get the IP from httpbin 
    my_config['my_ip'] = my_ip # Add the detected IP to the config
    dns_ip = get_ip_dns(my_config['hostname']) # Get the IP from DNS
    my_config['dns_ip'] = dns_ip # Add the DNS to the config
    if is_ipv4(my_ip) and my_ip != dns_ip:
        # we have a valid IP, and it differs from the one in DNS, so we need to update
        update_r53(my_ip, my_config)
    elif is_ipv4(my_ip) and my_ip == dns_ip:
        # Do nothing, IP matches
        DEBUG('IPs are the same, no update needed')
    else:
        # Something went sideways, yo, file like a bug report if your network is working
        print("Something else went wrong, maybe internet is down?")
        exit(1)
    write_config(my_config, args.config_file)
    exit(0)
        
