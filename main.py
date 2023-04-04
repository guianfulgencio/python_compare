import os, os.path
import time
import timeit
import glob
from ciscoconfparse import CiscoConfParse
from rich import print as rprint
from netmiko import Netmiko
from getpass import getpass
from netmiko import ConnectHandler
from netmiko import (
    ConnectHandler,
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
)
from ntc_templates.parse import parse_output
import sys
import netmiko
import git
from datetime import datetime
from rich.logging import RichHandler
import csv
from orionsdk import SwisClient
import urllib3
import requests
import re


username = str(sys.argv[1])
password = str(sys.argv[2])
secret = str(sys.argv[2])

listofip = str(sys.argv[3])
listofcommand = str(sys.argv[4])

thecsvfile = str(sys.argv[5])

Network_config_folder = f"python-network-testrepo-paei"
full_path = os.path.dirname(__file__)
Network_config_folder_path = os.path.join(full_path, f"python-network-testrepo-paei")



class CVXNetwork:
        def __init__(self, ip, device_type=None,username=None, password=None, secret=None):
                self.conn_data = {
                        'ip': ip,
                        'username': username,
                        'password': password,
                        'secret': password,
                        'device_type': device_type
                        }
        def login(self):
                return netmiko.ConnectHandler(**self.conn_data)

class CiscoIOS(CVXNetwork):
        def __init__(self, ip, username=username, password=password, secret=password):
                super().__init__(ip, device_type='cisco_ios',
                username=username, password=password, secret=password)
        
        def send_show_command(self, commands):
                '''commands show be in a form of list. Ex ['sh ip int br', 'show clock']'''
                result = {}
                conn = self.login()
                conn.enable()
                for command in commands:
                        output = conn.send_command(command, use_textfsm = True)
                        time.sleep(8)
                        result[command] = output
                conn.disconnect()
                self.send_show_command_output = result

        def add_set_config(self, commands):            
                #"""commands should be on a list form. 
                   #example commands = [f'int {interface}', 'shutdown']"""
                conn = self.login()
                conn.enable()
                output = conn.send_config_set(commands)
                print(output)
                conn.disconnect()
        
        def add_multiple_set_config(self, commands):            
                #"""commands should be on a list form. 
                   #example commands = [[f'int {interface}', 'shutdown'][f'int {interface}', 'shutdown]]"""
                conn = self.login()
                conn.enable()
                for command in commands:
                        output = conn.send_config_set(command)
                        print(output)
                conn.disconnect()

class CompareCiscoConfig:

        def __init__(self, folder, device):
                self.golden = CiscoConfParse(f"{folder}/golden.cfg")
                self.config1 = CiscoConfParse(f"{folder}/devices/{device}.cfg")
        
        def get_config_golden(self, parent):
                my_config1 =self.golden.find_all_children(parent)
                my_config1 = [items.lstrip('0123456789 ') for items in my_config1]
                my_config1 = [r.rstrip() for r in my_config1]
                return my_config1
        
        def get_config_device(self, parent):
                my_config1 =self.config1.find_all_children(r"^{}$".format(parent))
                my_config1 = [items.lstrip('0123456789 ') for items in my_config1]
                my_config1 = [r.rstrip() for r in my_config1]
                return my_config1
        
        def get_mgmt_interface(self):
                mgmt_interface = []
                for obj in self.config1.find_objects("^interf"):
                        if obj.re_search_children(r"vrf\sforwarding\sMgmt-vrf"):
                                mgmt_interface.append(obj.text)
                #print(mgmt_interface)
                return mgmt_interface
                                

        def get_interface_qos(self):
                new_list_interface = []
                for obj in self.config1.find_objects("^interf"):
                        if obj.re_search_children(r"service-policy\soutput\sLANQOS-OUT"):
                                host = {
                                        'InterfaceNumber': obj.text,
                                        'policy': 'service-policy output LANQOS-OUT'
                                }
                                new_list_interface.append(host)
                        if obj.re_search_children(r"service-policy\sinput\sSETDSCP"):
                                host = {
                                        'InterfaceNumber': obj.text,
                                        'policy': 'service-policy input SETDSCP'
                                }
                                new_list_interface.append(host)
                result = {}
                for d in new_list_interface:
                        interface = d['InterfaceNumber']
                        policy = d['policy']
                        if interface in result:
                                result[interface]['policy'].append(policy)
                        else:
                                result[interface]={'InterfaceNumber': interface, 'policy': [policy]}
                master_list_interface = list(result.values())
                #print(master_list_interface)
                return master_list_interface
        
        def get_auto_parent(self):
                new_list_interface = []
                policy_lines = self.config1.find_objects(r"^policy-map.*AutoQos")
                for line in policy_lines:
                        new_list_interface.append(line.text)
                class_lines = self.config1.find_objects(r"^class-map.*AutoQos")
                for line in class_lines:
                        new_list_interface.append(line.text)
                access_lines = self.config1.find_objects(r"^ip.*AutoQos")
                for line in access_lines:
                        new_list_interface.append(line.text)
                #print(new_list_interface
                result_auto_qos_list = ["no " + item for item in new_list_interface]
                return result_auto_qos_list
        
        def get_interface_auto(self):
                new_list_interface = []
                parent_objs = self.config1.find_objects("^interf")
                for parent_obj in parent_objs:
                        children_objs = parent_obj.children

                        for child_obj in children_objs:
                                if "auto qos" in child_obj.text:
                                        host = {
                                                'InterfaceNumber': parent_obj.text,
                                                'policy':child_obj.text.strip()
                                        }
                                        new_list_interface.append(host)
                                elif "service-policy input AutoQos" in child_obj.text:
                                        host = {
                                                'InterfaceNumber': parent_obj.text,
                                                'policy':child_obj.text.strip()
                                        }
                                        new_list_interface.append(host)
                                elif "service-policy output AutoQos" in child_obj.text:
                                        host = {
                                                'InterfaceNumber': parent_obj.text,
                                                'policy':child_obj.text.strip()
                                        }
                                        new_list_interface.append(host)
                result = {}
                for d in new_list_interface:
                        interface = d['InterfaceNumber']
                        policy = d['policy']
                        if interface in result:
                                result[interface]['policy'].append(policy)
                        else:
                                result[interface]={'InterfaceNumber': interface, 'policy': [policy]}
                master_list_interface = list(result.values())
                return master_list_interface

        def add_all_interface_qos(self):
                interface_list = []
                #get all interface
                interfaces = self.config1.find_objects(r"^interface")
                for interface in interfaces:
                        interface_list.append(interface.text)
                
                new_list = [item for item in interface_list if 'Ethernet' in item]

                #get interface with Auto
                interface_with_auto= self.get_interface_auto()
                get_list_interface_with_auto = []
                for d in interface_with_auto:
                        get_list_interface_with_auto.append(d['InterfaceNumber'])
                        for p in d['policy']:
                                if 'no ' in p:
                                        get_list_interface_with_auto.append(p)
                                else:
                                        if 'service-policy' in p:
                                                get_list_interface_with_auto.append('no ' + p)
                                        else:
                                                get_list_interface_with_auto.append('no ' + p)
                #print(get_list_interface_with_auto)
                
                
                #get interface with qos
                interface_qos = self.get_interface_qos()
                get_list_interface_qos = [d['InterfaceNumber'] for d in interface_qos]

                #get interface with one policy_map applied
                interface_one_policy = []
                for alist in interface_qos:
                        if 'service-policy input SETDSCP' not in alist['policy']:
                                interface_one_policy.append(alist['InterfaceNumber'])
                                interface_one_policy.append('service-policy input SETDSCP')
                        if 'service-policy output LANQOS-OUT' not in alist['policy']:
                                interface_one_policy.append(alist['InterfaceNumber'])
                                interface_one_policy.append('service-policy output LANQOS-OUT')
                
                #get mgmt interface
                mgmt_interface = self.get_mgmt_interface()


                #get the difference of all interface and interface with qos
                master_list = list(set(new_list) - set(get_list_interface_qos))

                #remove mgmt interface from master list
                master_list = list(set(master_list) - set(mgmt_interface))

                

                result = []

                for i in master_list:
                        result.append(i)
                        result.append('service-policy input SETDSCP')
                        result.append('service-policy output LANQOS-OUT')
                
                #add interface with one policy

                result = get_list_interface_with_auto + result + interface_one_policy
                #print(result)


                return result
        
        def config_scubber(self):
                pattern = [{"policy-map LAN":['policy-map LANQOS-OUT']},
                            {"policy-map SET":['policy-map SETDSCP']},
                            {"class-map match-any LAN-MARK":['class-map match-any LAN-MARK-EF',
                               'class-map match-any LAN-MARK-AF4',
                               'class-map match-any LAN-MARK-AF3',
                               'class-map match-any LAN-MARK-AF2',
                               'class-map match-any LAN-MARK-AF1',
                               'class-map match-any LAN-MARK-CS3']},
                             {"class-map match-any DSCP":['class-map match-any DSCP-EF',
                               'class-map match-any DSCP-AF4x',
                               'class-map match-any DSCP-AF3x',
                               'class-map match-any DSCP-AF2x',
                               'class-map match-any DSCP-AF1x',
                               'class-map match-any DSCP-CSx']},
                              {"ip access-list extended MARK-DSCP":['ip access-list extended MARK-DSCP-EF', 
                               'ip access-list extended MARK-DSCP-AF41', 
                               'ip access-list extended MARK-DSCP-AF31', 
                               'ip access-list extended MARK-DSCP-AF21',
                               'ip access-list extended MARK-DSCP-AF11',
                               'ip access-list extended MARK-DSCP-CS3']}]
                
                result=[]
                for dictionary in pattern:
                        for key, value in dictionary.items():
                                matched_lines = self.config1.find_objects(key)
                                checker_line = []
                                for the_line in matched_lines:
                                        checker_line.append(the_line.text)
                                checker_line = [r.rstrip() for r in checker_line]
                                #print(checker_line)
                                #print(value)
                                adiff = list(set(checker_line) - set(value))
                                result.append(adiff)

                                #matched_parent_lines = [line for line in matched_lines if not line]
                                #matched_parent_lines = [line for line in matched_lines if not line.is_parent]
                                #print(matched_parent_lines)
                                #matched_the_lines = []
                                #for line in matched_parent_lines:
                                        #matched_the_lines.append(line.text)
                                #print(matched_the_lines)
                                #matched_the_lines = [r.rstrip() for r in matched_the_lines]
                                #print(matched_the_lines)
                                #result.append(matched_the_lines)
                
                result = ['no ' + elem for sublist in result for elem in sublist]
                print(result)
                # get access,class,policy with autoqos
                #auto_qos_list = self.get_auto_parent()
                #result_auto_qos_list = ["no " + item for item in auto_qos_list]

                #result = result + result_auto_qos_list
                #print(result)
                return result
        
        def excess_config(self):
                parent_list_access = ['ip access-list extended MARK-DSCP-EF', 
                               'ip access-list extended MARK-DSCP-AF41', 
                               'ip access-list extended MARK-DSCP-AF31', 
                               'ip access-list extended MARK-DSCP-AF21',
                               'ip access-list extended MARK-DSCP-AF11',
                               'ip access-list extended MARK-DSCP-CS3',
                               'class-map match-any LAN-MARK-EF',
                               'class-map match-any LAN-MARK-AF4',
                               'class-map match-any LAN-MARK-AF3',
                               'class-map match-any LAN-MARK-AF2',
                               'class-map match-any LAN-MARK-AF1',
                               'class-map match-any LAN-MARK-CS3',
                               'class-map match-any DSCP-EF',
                               'class-map match-any DSCP-AF4x',
                               'class-map match-any DSCP-AF3x',
                               'class-map match-any DSCP-AF2x',
                               'class-map match-any DSCP-AF1x',
                               'class-map match-any DSCP-CSx']
                
                final_list = []
                for the_list in parent_list_access:
                        testing_diff = []
                        list1 = []
                        my_config2 =self.config1.find_all_children(r"^{}$".format(the_list))
                        my_config1 = [items.lstrip('0123456789 ') for items in my_config2]
                        my_config1 = [r.rstrip() for r in my_config1]
                        for x in self.config1.find_objects(the_list):
                                for child in x.children:
                                        list1.append(child.text)
                        new_mylist = [item.lstrip('0123456789 ') for item in list1]
                        new_mylist = [s.rstrip() for s in new_mylist]
                        list2 = []
                        for y in self.golden.find_objects(the_list):
                                #print("parent line:", obj.text)
                                for child in y.children:
                                        list2.append(child.text)
                        new_mylist2 = [item.lstrip('0123456789 ') for item in list2]
                        new_mylist2 = [s.rstrip() for s in new_mylist2]
                        testing_diff = (list(set(new_mylist).difference(new_mylist2)))
                        #print(testing_diff)

                        if testing_diff != []:
                                # this is an access-list and adding sequence number back 
                                if "access-list" in the_list:
                                        print(f"{the_list} - adding sequence number for excess a")
                                        an_result = [item for item in my_config2 for string in testing_diff if string in item]
                                        an_result = [r.rstrip() for r in an_result]
                                        
                                        modified_list = ['no ' + item for item in an_result]
                                        final_list.append([the_list]+ modified_list)
                                else:
                                        modified_list = ['no ' + item for item in testing_diff]
                                        final_list.append([the_list]+ modified_list)


                single_list = [item for sublist in final_list for item in sublist]
                return single_list
        
        def excess_config_3lines(self):
                parent = ['policy-map LANQOS-OUT', 
                               'policy-map SETDSCP']
                main_command = []
                result = {}
                for the_list in parent:
                        result[the_list] = []
                        my_config1 =self.config1.find_all_children(r"^{}$".format(the_list))
                        my_config1 = [item.lstrip('0123456789 ') for item in my_config1]
                        my_config1 = [s.rstrip() for s in my_config1]
                        if my_config1 != []:
                                my_config1.remove(the_list)

                        my_golden = self.golden.find_all_children(the_list)
                        my_golden.remove(the_list)
                        my_golden = [item.lstrip('0123456789 ') for item in my_golden]
                        my_golden = [s.rstrip() for s in my_golden]

                        result1 = []
                        result2 = []
                        current_class = None
                        for item in my_golden:
                                if item.startswith('class'):
                                        current_class = item.split()[1]
                                        result1.append(item)
                                elif current_class:
                                        result1.append(f'{item} class {current_class}')
                                else:
                                        result1.append(item)
                        #print(result1)
                        current_class = None
                        for item in my_config1:
                                if item.startswith('class'):
                                        current_class = item.split()[1]
                                        result2.append(item)
                                elif current_class:
                                        result2.append(f'{item} class {current_class}')
                                else:
                                        result2.append(item)
                        #print(result2)
                        commands = (list(set(result2).difference(result1)))
                        #print(commands)
                        
                        the_result = [item for item in commands if item.startswith('class')]
                        commands = [item for item in commands if item not in the_result]

                        output = []
                        for command in commands:
                                words = command.split()
                                if 'class' in words:
                                        index = words.index('class')
                                        output.append([f'class {words[index+1]}', ' '.join(words[:index])])

                        data = the_result + output
                        data_sorted = sorted(data, key=lambda x: x[0])


                        result[the_list].append(data_sorted)
                #print(result)

                for an_item in parent:
                        print(an_item)
                        print(result[an_item])
                        output =[]
                        for the_item in result[an_item]:
                                for i in the_item:
                                        if i == 'class DSCP-EF':
                                                continue
                                        elif type(i) == str:
                                                output.append('no ' + i)
                                        else:
                                                if 'class DSCP-EF' in i:
                                                        continue
                                                else:
                                                        txt = []
                                                        for y in i:
                                                                if "class" in y:
                                                                        txt.append(y)
                                                                else:
                                                                        txt.append('no ' + y)
                                                        output.append(txt)


                        add_this = [an_item] + output
                        flattened_list = flatten(add_this)
                        final_result = flattened_list
                        main_command.append(final_result)
                
                single_list = [item for sublist in main_command for item in sublist]
                if single_list == ['policy-map LANQOS-OUT', 'policy-map SETDSCP']:
                        single_list = []
                return single_list
                        
                

                        

                


def flatten(lst):
        # make multiple list['policy-map SETDSCP', ['class LAN-MARK-AF3', ['class LAN-MARK-AF3', 'set dscp af31']]] into a single list ['policy-map SETDSCP', 'class LAN-MARK-AF3', 'class LAN-MARK-AF3', 'set dscp af31']
    flattened = []
    for item in lst:
        if isinstance(item, list):
            flattened.extend(flatten(item))
        else:
            flattened.append(item)
    return flattened


def get_main_command(folder, row, a_host):
        Difference = CompareCiscoConfig(folder,a_host)
        main_command = []
        parent_list_access = ['ip access-list extended MARK-DSCP-EF', 
                               'ip access-list extended MARK-DSCP-AF41', 
                               'ip access-list extended MARK-DSCP-AF31', 
                               'ip access-list extended MARK-DSCP-AF21',
                               'ip access-list extended MARK-DSCP-AF11',
                               'ip access-list extended MARK-DSCP-CS3',
                               'class-map match-any LAN-MARK-EF',
                               'class-map match-any LAN-MARK-AF4',
                               'class-map match-any LAN-MARK-AF3',
                               'class-map match-any LAN-MARK-AF2',
                               'class-map match-any LAN-MARK-AF1',
                               'class-map match-any LAN-MARK-CS3',
                               'class-map match-any DSCP-EF',
                               'class-map match-any DSCP-AF4x',
                               'class-map match-any DSCP-AF3x',
                               'class-map match-any DSCP-AF2x',
                               'class-map match-any DSCP-AF1x',
                               'class-map match-any DSCP-CSx',
                               'policy-map LANQOS-OUT',
                               'policy-map SETDSCP']
        add_list_access = ['policy-map LANQOS-OUT /class class-default config contains must not random-detect dscp-based or random-detect',
                           'policy-map LANQOS-OUT / class DSCP-EF ! must contain 1 of the following 3 priority level 1 percent 10 /priority percent 10 / priority']

        for x in parent_list_access:
                #print(row[x])
                if 'applied' in row[x]: 
                        main_command.append(Difference.get_config_golden(x))
                elif 'Compliant' not in row[x]:
                        if "policy-map" in x:
                                add_this = [x] + eval(row[x])
                                flattened_list = flatten(add_this)
                                final_result = flattened_list
                                main_command.append(final_result)
                                #add this for issue bandwith should comes first before random
                                if 'random-detect dscp-based' in final_result:
                                        main_command.append(final_result)
                                


                        else:
                                add_this = [x] + eval(row[x])
                                final_result = add_this
                                main_command.append(final_result)

                        #print(x)
                        #print(type(x))
                        #print(row[x])
                        #print(type(row[x]))



        for y in add_list_access:
                #print(row[y])
                if 'NO class DSCP-EF' == row[y]:
                        main_command.append(['policy-map LANQOS-OUT','class DSCP-EF','priority level 1 percent 10'])
                
                if y == 'policy-map LANQOS-OUT /class class-default config contains must not random-detect dscp-based or random-detect' and row[y] == 'Non-Compliant':
                        print('policy-map LANQOS-OUT /class class-default config contains must not random-detect dscp-based or random-detect should be corrected by the clean-up')
                        #This portion is remove because it will be captured by the clean up
                        #the_random = Difference.get_config_device('policy-map LANQOS-OUT')
                        #print(the_random)
                        # add 2nd line to 3rd line
                        #result1 = []
                        #current_class = None
                        #for item in the_random:
                                #if item.startswith('class'):
                                        #current_class = item.split()[1]
                                        #result1.append(item)
                                #elif current_class:
                                        #result1.append(f'{item} class {current_class}')
                                #else:
                                        #result1.append(item)
                        #print(result1)
                        #result2 = [item.replace("class class-default", "").strip() for item in result1 if "random-detect" in item and "class class-default" in item][0]
                        #result2 = 'no ' + result2
                        #print(result2)
                        #print(type(result2))
                        #main_command.append(['policy-map LANQOS-OUT','class class-default',result2])
                
                if y == 'policy-map LANQOS-OUT / class DSCP-EF ! must contain 1 of the following 3 priority level 1 percent 10 /priority percent 10 / priority' and row[y] == 'Non-Compliant':
                        main_command.append(['policy-map LANQOS-OUT','class DSCP-EF','priority level 1 percent 10'])


                

        return main_command

def convert_versiontofloat(version):
        match = re.search(r'\.\d+$', version)
        if match:
                suffix = match.group(0)  # get the matched suffix
                new_string = version[:-len(suffix)]  # remove the matched suffix
                print(new_string)  # output: "16.12"
        else:
                print("String does not end with a number after a dot")
                new_string = "16.11"
                print(new_string)
        return new_string

def git_push_repo():
        repo = git.Repo(f'python-network-testrepo-paei', search_parent_directories=True)
        repo.config_writer().set_value("user", "name", "Paulo Escano").release()
        repo.config_writer().set_value("user", "email", "paei@chevron.com").release()
        repo.git.add('.')
        current_date = datetime.today().strftime('%Y-%m-%d')
        repo.index.commit(f"Backup configuration - {current_date}")
        repo.git.push()
        rprint("✔️ Repo has been updated with new device configurations")

        

def main():
    if listofcommand == "None" and listofip == "None":
            with open(f"{Network_config_folder_path}/results/{thecsvfile}", 'r') as csvfile:
                    csvreader = csv.DictReader(csvfile)
                    for row in csvreader:
                        print(row['Hostname'])
                        print(row['DeviceVersion'])
                        num1, num2 = [int(num) for num in convert_versiontofloat(row['DeviceVersion']).split(".")]
                        if (num1 >= 16 and num2 >=12) or (num1 >=16 and num2 >=12) or (num1 > 16):
                                if "Device is Compliant" in (row['Overall Status']):
                                        the_interface = CompareCiscoConfig(Network_config_folder_path, row['Hostname'])
                                        auto_list = the_interface.get_auto_parent()
                                        interface_list = the_interface.add_all_interface_qos()
                                        scrub_config = the_interface.config_scubber()
                                        excess_acl_config = the_interface.excess_config()
                                        excess_policy_config = the_interface.excess_config_3lines()
                                        rprint(f"[#43FF33]✔️ Excess policy config : {excess_policy_config}")
                                        rprint(f"[#43FF33]✔️ Excess_config : {excess_acl_config}")
                                        rprint(f"[#43FF33]✔️ Interface config : {interface_list}")
                                        rprint(f"[#43FF33]✔️ Scrub ACL,CLass,Policy,AutoQos config : {scrub_config}")
                                        final_command = [excess_policy_config,excess_acl_config,scrub_config,interface_list,auto_list]
                                        rprint(f"[#43FF33]✔️ Add config interface, Scrub, Auto: {final_command}")
                                        has_values = any(item for item in final_command)
                                        if has_values:
                                                run_command = CiscoIOS(row['IpAddress'])
                                                run_command.add_multiple_set_config(final_command)
                                                rprint(f"[#43FF33]✔️ Completed")
                                                run_command.send_show_command(['show run'])
                                                with open(f"{Network_config_folder_path}/devices/{row['Hostname']}.cfg", 'w') as nf:
                                                        nf.write(run_command.send_show_command_output['show run'])
                                                git_push_repo()
                                        else:
                                                rprint(f"[#43FF33]✔️ Device {row['Hostname']} is fully QOS compliant")


                                else:
                                        for i in range(2):
                                                the_cleanup = CompareCiscoConfig(Network_config_folder_path, row['Hostname'])
                                                the_excess_policy_config = the_cleanup.excess_config_3lines()
                                                the_excess_acl_config = the_cleanup.excess_config()
                                                the_scrub_config = the_cleanup.config_scubber()
                                                the_final_command = [the_excess_policy_config,the_excess_acl_config, the_scrub_config]
                                                rprint(f"[#43FF33]✔️ Clean-up ACL,CLass,Policy,AutoQos config : {the_final_command}")
                                                has_value = any(item for item in the_final_command)
                                                if has_value:
                                                        run_command = CiscoIOS(row['IpAddress'])
                                                        run_command.add_multiple_set_config(the_final_command)
                                                        rprint(f"[#43FF33]✔️ Completed Clean-up ACL,CLass,Policy,AutoQos config")
                                                        run_command.send_show_command(['show run'])

                                                        with open(f"{Network_config_folder_path}/devices/{row['Hostname']}.cfg", 'w') as nf:
                                                                nf.write(run_command.send_show_command_output['show run'])
                                                        git_push_repo()
                                                else:
                                                      rprint(f"[#43FF33]✔️ Moving on next section No Clean-up ACL,CLass,Policy,AutoQos config needed")
                                                      break
                                                


                                        



                                        main_command = get_main_command(Network_config_folder_path, row, row['Hostname'])
                                        rprint(f"[#43FF33]✔️ Add config ACL,Class,Policy : {main_command}")
                                        #print(main_command)
                                        main_device = CiscoIOS(row['IpAddress'])
                                        main_device.add_multiple_set_config(main_command)
                                        rprint(f"[#43FF33]✔️ Completed Add config ACL,Class,Policy")

                                        the_auto_list = the_cleanup.get_auto_parent()
                                        the_interface_list = the_cleanup.add_all_interface_qos()
                                        another_the_final_command  = [the_interface_list + the_auto_list]




                                        rprint(f"[#43FF33]✔️ Add Interface and Auto-QOS clean-up")
                                        the_run_command = CiscoIOS(row['IpAddress'])
                                        the_run_command.add_multiple_set_config(another_the_final_command)

                                        rprint(f"[#43FF33]✔️ Completed Interface clean-up")

                                        the_run_command.send_show_command(['show run'])
                                        with open(f"{Network_config_folder_path}/devices/{row['Hostname']}.cfg", 'w') as nf:
                                                nf.write(the_run_command.send_show_command_output['show run'])
                                        
                                        git_push_repo()
                                        rprint(f"[#43FF33]✔️ Updated to Repo Completed")

                                        #main_device.send_show_command(['show run'])
                                        #print(main_device.send_show_command_output['show run'])
                        
                        else:
                                print(f"Device version {row['DeviceVersion']} should be checked or upgraded")



    else:
            if listofip == "None":
                    ip_list = []
                    with open(f"{Network_config_folder_path}/results/{thecsvfile}", 'r') as csvfile:
                            csvreader = csv.DictReader(csvfile)
                            for row in csvreader:
                                    ip_list.append(row['IpAddress'])

        
            else:
                    ip_list = listofip.strip('[]').split(',')
            print(ip_list)
            command_list = listofcommand.strip('[]').split(',')
            print(command_list)
            device_test1 = CiscoIOS(ip_list[0])
            device_test1.add_set_config(command_list)
        #device_test1.send_show_command(['show run'])
        #print(device_test1.send_show_command_output['show run'])



if __name__ == '__main__':
        main()

