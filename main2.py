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


username = str(sys.argv[1])
password = str(sys.argv[2])
secret = str(sys.argv[2])
choose_golden = "golden"
ownfile = str(sys.argv[3])



Network_config_folder = f"python-network-testrepo-paei"
full_path = os.path.dirname(__file__)
Network_config_folder_path = os.path.join(full_path, f"python-network-testrepo-paei")


class CompareCiscoConfig:

        def __init__(self, folder):
                self.config1 = CiscoConfParse(f"{folder}/config1.cfg")
                self.golden = CiscoConfParse(f"{folder}/{choose_golden}.cfg")

        def compare_config(self, parent):
                """parent should be a list eg ['ip access-list extended MARK-DSCP-EF', 'ip access-list extended MARK-DSCP-AF41' ]"""
                result = {}
                
                for the_list in parent:
                        result[the_list] = []
                        testing_diff = []
                        list1 = []
                        my_config1 =self.config1.find_all_children(r"^{}$".format(the_list))
                        my_config1 = [items.lstrip('0123456789 ') for items in my_config1]
                        my_config1 = [r.rstrip() for r in my_config1]
                        if the_list not in my_config1:
                                result[the_list].append(f'No {the_list} applied')
                                continue


                        for x in self.config1.find_objects(r"^{}$".format(the_list)):
                                #print("parent line:", obj.text)
                                for child in x.children:
                                        list1.append(child.text)
                        new_mylist = [item.lstrip('0123456789 ') for item in list1]
                        new_mylist = [s.rstrip() for s in new_mylist]
                        #print(new_mylist)
                        list2 = []
                        for y in self.golden.find_objects(the_list):
                                #print("parent line:", obj.text)
                                for child in y.children:
                                        list2.append(child.text)
                        new_mylist2 = [item.lstrip('0123456789 ') for item in list2]
                        new_mylist2 = [s.rstrip() for s in new_mylist2]
                        #print(new_mylist2)
                        #result[the_list]= [the_list] + (list(set(new_mylist2).difference(new_mylist))) #adding the parent line on the list
                        result[the_list]= (list(set(new_mylist2).difference(new_mylist)))

                        if result[the_list] == []:
                                rprint(f"[#43FF33]✔️ Difference on {the_list}: {result[the_list]}")
                                #print(new_mylist)
                                #print(new_mylist2)
                        else:
                                rprint(f"[#F39C12]❌ Difference on {the_list}: {result[the_list]}")
                                #print(new_mylist)
                                #print(new_mylist2)
                self.show_compare_config = result

                
        
        def compare_config_3lines(self, parent):
                result = {}
                for the_list in parent:
                        result[the_list] = []
                        my_config1 =self.config1.find_all_children(r"^{}$".format(the_list))
                        #print(my_config1)
                        my_config1 = [item.lstrip('0123456789 ') for item in my_config1]
                        #print(my_config1)
                        my_config1 = [s.rstrip() for s in my_config1]
                        if the_list not in my_config1:
                                result[the_list].append(f'No {the_list} applied')
                                continue
                        my_config1.remove(the_list)
                        #print(my_config1)
                        my_golden = self.golden.find_all_children(the_list)
                        my_golden.remove(the_list)
                        my_golden = [item.lstrip('0123456789 ') for item in my_golden]
                        my_golden = [s.rstrip() for s in my_golden]
                        #print(my_golden)
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
                        commands = (list(set(result1).difference(result2)))
                        #print(commands)
                        
                        the_result = [item for item in commands if item.startswith('class')]
                        commands = [item for item in commands if item not in the_result]

                        output = []
                        for command in commands:
                                words = command.split()
                                if 'class' in words:
                                        index = words.index('class')
                                        output.append([f'class {words[index+1]}', ' '.join(words[:index])])

                        #print(output)

                        data = the_result + output
                        data_sorted = sorted(data, key=lambda x: x[0])
                        #print("datasorted")
                        #print(data_sorted)


                        result[the_list].append(data_sorted)
                self.show_compare_config_3lines = result
                for the_list in parent:
                        if result[the_list] == []:
                                rprint(f"[#43FF33]✔️ Difference on {the_list}: {result[the_list]}")
                        else:
                                rprint(f"[#F39C12]❌ Difference on {the_list}: {result[the_list]}")
                     
        
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
                print(master_list_interface)
                self.show_get_interface_qos = master_list_interface

        
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
                print(master_list_interface)
                self.show_get_interface_auto = master_list_interface

        
        def get_interface_noconfig(self):
                new_list_interface = []
                interfaces = self.config1.find_objects(r"^interface")
                for interface in interfaces:
                        if not interface.children:
                                new_list_interface.append(interface.text)
                print(new_list_interface)
        
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
                print(new_list_interface)
        
        def get_hostname(self):
                hostname = self.config1.find_objects(r"^hostname")[0].text.split()[1]
                self.show_get_hostname = hostname
                print(hostname)
        
        def get_LANQOS_default(self):
                ''' policy-map LANQOS-OUT /class class-default config contains must not random-detect dscp-based or random-detect '''
                class_default = self.config1.find_all_children(r'^policy-map LANQOS-OUT$')
                class_default = [item.lstrip('0123456789 ') for item in class_default]
                class_default  = [s.rstrip() for s in class_default]
                if class_default == []:
                        result = 'NO policy-map LANQOS-OUT'
                elif 'class class-default' in class_default:
                        index = class_default.index('class class-default')
                        items_after_class_default = class_default[index+1:]
                        #print(items_after_class_default)
                        if 'random-detect dscp-based' in items_after_class_default or 'random-detect' in items_after_class_default:
                                result = "Non-Compliant"
                        else:
                                result = "Compliant"

                else:
                        result= 'NO class class-default'
                
                self.show_get_LANQOS_default = result
                
        
        def get_LANQOS_DSCP_EF(self):
                '''policy-map LANQOS-OUT / class DSCP-EF ! must contain 1 of the following 3 priority level 1 percent 10 /priority percent 10 / priority '''
                
                class_dscp_ef = self.config1.find_all_children(r'^ class DSCP-EF$') #space on class is important

                class_dscp_ef = [item.lstrip('0123456789 ') for item in class_dscp_ef]
                class_dscp_ef  = [s.rstrip() for s in class_dscp_ef]
                print(class_dscp_ef)
                if 'class DSCP-EF' in class_dscp_ef: 
                        if "priority level 1 percent 10" in class_dscp_ef or \
                                "priority percent 10" in class_dscp_ef or \
                                "priority" in class_dscp_ef:
                                result = "Compliant"
                        else:
                                result = "Non-Compliant"
                else:
                        result = 'NO class DSCP-EF'


                print(result)
                self.show_get_LANQOS_DSCP_EF = result



      

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
        
        def show_cisco_run(self):
                conn = self.login()
                sh_run = conn.send_command('sh run', use_textfsm = False)
                self.sh_cisco_run = sh_run
                conn.disconnect()

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
        

def git_push_repo():
        repo = git.Repo(f'python-network-testrepo-paei', search_parent_directories=True)
        repo.config_writer().set_value("user", "name", "Paulo Escano").release()
        repo.config_writer().set_value("user", "email", "paei@chevron.com").release()
        repo.git.add('.')
        current_date = datetime.today().strftime('%Y-%m-%d')
        repo.index.commit(f"Backup configuration - {current_date}")
        repo.git.push()
        rprint("✔️ Repo has been updated with new device configurations")


def check_folder_existence_path():
        if not os.path.exists(Network_config_folder):
                os.makedirs(Network_config_folder)
                rprint(f"[#43FF33]✔️ Folder Network Config Files successfully created [/#43FF33]")
        else:
                rprint(f"[#F39C12]❗  Folder Network Config Files already existed! [/#F39C12]")




def main():
    
    #####################Access the device, get show run, save it to the folder##########################
    ############################list of IP to be used#############################################

    SiteName = ownfile.split(".")[0]
    ip_list =[]
    with open(f"{Network_config_folder_path}/results/{ownfile}", 'r') as csvfile:
        csvreader = csv.DictReader(csvfile)
        for row in csvreader:
            print(row['IpAddress'])
            ip_list.append(row['IpAddress'])
        print(SiteName)




    
    last_rows = []
    print(f"list of ip's: {ip_list}")
    print(f"number of devices: {len(ip_list)}")

    ###############################################################################################
    for my_ip in ip_list:
        try:
                my_rows = []
                check_compliance = []
                check_folder_existence_path()
                print(f"##############################{my_ip}########################################")
                device_test1 = CiscoIOS(my_ip)
                device_test1.send_show_command(['show run', 'show ver'])
                with open(f"{Network_config_folder_path}/config1.cfg", 'w') as nf:
                        nf.write(device_test1.send_show_command_output['show run'])
                ############################Push folder back to ADO repo#############################################
                git_push_repo()
                ###############################Access device get invetory for devicemodel############################
                device_model = device_test1.send_show_command_output['show ver'][0]['hardware'][0]
                device_version = device_test1.send_show_command_output['show ver'][0]['version']
                rprint(f"[#43FF33]✔️ DeviceModel: {device_model}")
                rprint(f"[#43FF33]✔️ DeviceVersion: {device_version}")
                ##############################Compare Configuration##################################################
                Difference = CompareCiscoConfig(Network_config_folder_path)
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
                parent_list_policy = ['policy-map LANQOS-OUT', 
                               'policy-map SETDSCP']
                print("######################get hostname#############################")
                Difference.get_hostname()
                host = {
                        'Hostname': Difference.show_get_hostname,
                        'IpAddress': my_ip,
                        'Status': 'Active',
                        'DeviceModel': device_model,
                        'DeviceVersion': device_version
                }
                my_rows.append(host)
                #########################SaVe Config#################################
                with open(f"{Network_config_folder_path}/devices/{Difference.show_get_hostname}.cfg", 'w') as rf:
                        rf.write(device_test1.send_show_command_output['show run'])
                ################################################################################
                print("######################2 line#############################")
                try:
                        Difference.compare_config(parent_list_access)
                        for txt in parent_list_access:
                                if Difference.show_compare_config[txt] != []:
                                        host = {txt: Difference.show_compare_config[txt]}
                                        check_compliance.append('Non-Compliant')
                                        my_rows.append(host)
                                else:
                                        host = {txt: 'Compliant'}
                                        check_compliance.append('Compliant')
                                        my_rows.append(host)
                except:
                        host = {'Hostname': Difference.show_get_hostname, 'Status': 'Active'}
                        my_rows.append(host)
                ################################################################################
                print("######################3 line#############################")
                try:
                        Difference.compare_config_3lines(parent_list_policy)
                        for mytxt in parent_list_policy :
                                if Difference.show_compare_config_3lines[mytxt] != [[]]:
                                        host = {mytxt: Difference.show_compare_config_3lines[mytxt]}
                                        check_compliance.append('Non-Compliant')
                                        my_rows.append(host)
                                else:
                                        host = {mytxt: 'Compliant'}
                                        check_compliance.append('Compliant')
                                        my_rows.append(host)
                except:
                        host = {'Hostname': Difference.show_get_hostname, 'Status': 'Active'}
                        my_rows.append(host)
                ################################################################################
                print("#####Policy-map LANQOS-OUT class class-default  ! must not contain the following random-detect dscp-based / random-detect######")

                try:
                        Difference.get_LANQOS_default()
                        print(Difference.show_get_LANQOS_default)
                        host = {'policy-map LANQOS-OUT /class class-default config contains must not random-detect dscp-based or random-detect': Difference.show_get_LANQOS_default}
                        check_compliance.append(Difference.show_get_LANQOS_default)
                        my_rows.append(host)
                except:
                        host = {'Hostname': Difference.show_get_hostname, 'Status': 'Active', 'policy-map LANQOS-OUT /class class-default config contains must not random-detect dscp-based or random-detect': 'Error'}
                        my_rows.append(host)

               ################################################################################         
                print("####Policy-map LANQOS-OUT / class DSCP-EF / ! must contain 1 of the following 3 priority level 1 percent 10/priority percent 10/ priority #####")
                try:
                        Difference.get_LANQOS_DSCP_EF()
                        host = {'policy-map LANQOS-OUT / class DSCP-EF ! must contain 1 of the following 3 priority level 1 percent 10 /priority percent 10 / priority': Difference.show_get_LANQOS_DSCP_EF}
                        check_compliance.append(Difference.show_get_LANQOS_DSCP_EF)
                        my_rows.append(host)
                except:
                        host = {'Hostname': Difference.show_get_hostname, 'Status': 'Active','policy-map LANQOS-OUT / class DSCP-EF ! must contain 1 of the following 3 priority level 1 percent 10 /priority percent 10 / priority':'Error'}
                        my_rows.append(host)
                #######################Check overall compliant#####################################
                print("check_compliance")
                print(check_compliance)
                if 'Non-Compliant' in check_compliance:
                        host = {'Overall Status': 'Device is Non-Compliant'}
                        my_rows.append(host)
                elif 'NO class DSCP-EF' in check_compliance or 'NO class class-default' in check_compliance :
                        host = {'Overall Status': 'Device is Non-Compliant'}
                        my_rows.append(host)
                else:
                        host = {'Overall Status': 'Device is Compliant'}
                        my_rows.append(host) 
                


                ################################################################################
                result_dict = {}
                for d in my_rows:
                        result_dict.update(d)
                result_list = [result_dict]
                my_rows = result_list
                last_rows.append(my_rows)
                print("################Interface with LANQOS or SETDSCP policy applied##################")
                Difference.get_interface_qos()
                print("######################Interface with AutoQOS applied#############################")
                Difference.get_interface_auto()
                ################################################################################
                print("#######################Interface with No Config#################################")
                Difference.get_interface_noconfig()
                ################################################################################
                print("#######################policy,access,class with Autoqos#####################")
                Difference.get_auto_parent()
                #print("#######################Config push#######################################")

                for map in parent_list_access:
                        if Difference.show_compare_config[map] != []:
                                command = [map] + Difference.show_compare_config[map]
                                #print(command)
                                print(f'[#43FF33]✔️push config {command}')
                                #################################################################
                                #device_test1.add_set_config(command)
                                print("##########################################################")
                                #no_command = []

                                #for i in range(len(Difference.show_compare_config[map])):
                                        #Difference.show_compare_config[map][i] = "no " + Difference.show_compare_config[map][i]
                                        #no_command.append(Difference.show_compare_config[map][i])
                                #no_command = [map] + Difference.show_compare_config[map]
                                #print(no_command)
                                #access_list_name = map.split()[-1]
                                #print(access_list_name)
                                #device_test1.send_show_command([f'show ip access-lists {access_list_name}'])
                                #accessname= device_test1.send_show_command_output[f'show ip access-lists {access_list_name}']
                                #print(accessname)
                                #print(f'[#43FF33]✔️ push config {command} for removing recently added config')
                                #device_test1.add_set_config(no_command)


                        else:
                                print(f'{map} has no difference on golden config')
                                print("##########################################################")
                for map in parent_list_policy:
                        if f'No {map} applied' in Difference.show_compare_config_3lines[map]:
                                print(f'No {map} applied need to push all {map} config')

                        elif Difference.show_compare_config_3lines[map] != [[]]:
                                for my_map in Difference.show_compare_config_3lines[map]:
                                        for next_map in my_map:
                                                if isinstance(next_map, list):
                                                        command = [map] + [next_map]
                                                        command = [command[0]] + [item for item in command[1]]
                                                        print(f'[#43FF33]✔️push config {command}')
                                                else:
                                                        command = [map] + [next_map]
                                                        print(f'[#43FF33]✔️push config {command}')

                                
                                #################################################################
                                #device_test1.add_set_config(command)
                                print("##########################################################")
                                #no_command = []
                                #for i in range(len(Difference.show_compare_config_3lines[map])):
                                        #Difference.show_compare_config_3lines[map][i] = "no " + Difference.show_compare_config_3lines[map][i]
                                        #no_command.append(Difference.show_compare_config_3lines[map][i])
                                #no_command = [map] + Difference.show_compare_config_3lines[map]
                                #print(no_command)
                        else:
                                print(f'{map} has no difference on golden config')
                                print("##########################################################")
                '''print("##################PUSH Remove Auto interface############################")
                interface_auto = Difference.show_get_interface_auto
                output_auto = []
                for interface in interface_auto:
                    output_auto.append(interface['InterfaceNumber'])
                    for policy in interface['policy']:
                            output_auto.append('no ' + policy )
                print(output_auto)
                if output_auto != []:
                    command = output_auto
                    print(f'[#43FF33]✔️push config {command}')
                    #device_test1.add_set_config(command)
                else:
                    print(f'auto-qos on interfaces removed')'''
        except:
                host = {'Hostname': my_ip, 'Status': 'Inactive'}
                my_rows.append(host)
                result_dict = {}
                for d in my_rows:
                        result_dict.update(d)
                result_list = [result_dict]
                my_rows = result_list
                last_rows.append(my_rows)


    ##################################################################################   
    print(last_rows)

    ###########################Add CSV on the repo####################################
    try:    
        with open(f"{Network_config_folder_path}/results/{SiteName}.csv", 'w', newline='') as csvfile:
        
                fieldnames = ['Hostname', 'IpAddress', 'Status', 'DeviceModel', 'DeviceVersion', 'Overall Status'] + parent_list_access + parent_list_policy + ['policy-map LANQOS-OUT /class class-default config contains must not random-detect dscp-based or random-detect'] + ['policy-map LANQOS-OUT / class DSCP-EF ! must contain 1 of the following 3 priority level 1 percent 10 /priority percent 10 / priority']     
        
                writer = csv.DictWriter(csvfile, fieldnames)
        
                writer.writeheader()
        
                for row in last_rows:
        
                        for myrow in row:
        
                            writer.writerow(myrow)
    except:
            rprint(f"[#F39C12]❗ Devices on the list are all unreachable.")


    git_push_repo()
    rprint(f"[#43FF33]✔️ CSV successfully uploaded to repo[/#43FF33]")

      


            


if __name__ == '__main__':
        main()
