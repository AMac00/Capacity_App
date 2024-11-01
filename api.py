import json
import socket
import requests, urllib3, os,sys, math, pandas, openpyxl
from requests.exceptions import HTTPError
from datetime import datetime
import logging
import re
# 'fxos': ['10.101.0.16','10.101.0.17','10.101.0.18','10.101.0.19','10.102.0.16','10.102.0.17','10.102.0.18','10.102.0.19']
# HTTP API Templating
from flask import Flask, render_template
from flask_restx import Resource, Api
# Threading
from concurrent.futures import ThreadPoolExecutor, as_completed
# Env imports
from dotenv import load_dotenv

##Current time
now = datetime.now()

## Logger setup
logger = logging.getLogger("api")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


# Global Request Session
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.session()

# Import .env file
load_dotenv()
'''
# .env file are local the the install
username=xxxx
password=xxxx

'''

'''
--------------------------------------------------------------------------------------------------------------------------------------------------------
Checks to see if applications is EXE (frozen) or running in development 
'''
if getattr(sys, 'frozen', False):
    workingdir = os.path.realpath(sys._MEIPASS)
else :
    workingdir =  os.path.dirname(os.path.realpath(__file__))
template_folder = os.path.join(workingdir, 'templates')
static_folder = os.path.join(workingdir,'static')
workfiles_folder = os.path.join(static_folder, 'workfiles')
print("This is static folder is %s" % static_folder)
print("This is template_folder folder is %s" % template_folder)



''' 
API Settings and Namespaces  
'''
app = Flask(__name__,template_folder=template_folder)
api = Api(app,
            version = '1.0',
            title = 'Capacity App',
            description= 'A data point collection application')

'''
Operational Functions 
'''
# Putting this in a class incase we want te expand and break them out later.
#'fxos': ['10.101.0.16', '10.101.0.17', '10.101.0.18', '10.101.0.19', '10.102.0.16', '10.102.0.17', '10.102.0.18','10.102.0.19'],

class fxos_functions:

    def __init__(self):
        self.version = '1.0'
        self.fxos_info = {
            'fxos': ['10.101.0.16','10.101.0.17','10.101.0.18','10.101.0.19','10.102.0.16','10.102.0.17','10.102.0.18','10.102.0.19'],
            'username': os.environ.get('USER_NAME'),
            'password': os.environ.get('PASSWORD'),
            'counter': 1,
            'notes': 'Report Time:  ' + str(now) + "\n" + '   Notes: Total 96 cpu per FXOS.     6cpu = Small-FW, 12cpu = Medium-FW, 24cpu = Large , 36cpu = XL Large',
            'title': 'FirePower Available Capacity Reports',
            'title2': 'Per Host Additional information',
            'fxos_small_cost': 6,
            'fxos_medium_cost': 12,
            'fxos_large_cost': 18,
            'fxos_xllarge_cost':24,
            'fxos_cpu_total': 86,
        }
        self.fxo_totals = {}

    def fxo_status(self):
        return(self.fxo_totals)

    def fxo_pull(self,fxo):
        try:
            logger.debug("Working on {0}".format(fxo))
            hostname = socket.gethostbyaddr(fxo)[0].split("-")[0].upper()
            __info__ = {
                        'ip': fxo,
                        'name': '{0}'.format(hostname.split("-")[0]),
                        'region': hostname[:2],
                        'datacenter': hostname[2:5],
                        'token': '',
                        'fw_instances_used': 0,
                        'fw_cpu_available': self.fxos_info['fxos_cpu_total'],
                        'fw_small_used': 0,
                        'fw_medium_used': 0,
                        'fw_large_used': 0,
                        'fw_xllarge_used': 0,
                        }
            # Login to get Token
            try:
                __method__ = '/api/login'
                __headers__ = {
                    'username': self.fxos_info['username'],
                    'password': self.fxos_info['password']
                }
                __response__ = session.request("POST", 'https://{0}{1}'.format(fxo, __method__), headers=__headers__,verify=False)
                __response__.raise_for_status()
                if "token" in __response__.json():
                    logger.debug(__response__.json())
                    __token__ = __response__.json()['token']
                    __info__['token'] = __token__
                else:
                    raise Exception("200 Login but without a token.. Not going to work")
            except HTTPError as http_err:
                logging.error('{0}'.format(http_err))
            except Exception as err:
                logging.error('{0}'.format(err))
            # Pull Information
            if len(__info__['token']) >= 1:
                try:
                    logger.debug("Login Successful lets pull the info for {0}".format(__info__['name']))
                    method = '/api?classId=smAppInstance'
                    __headers__ = {'token': __info__['token']}
                    __response__ = session.request("Get", 'https://{0}{1}'.format(fxo, method), headers=__headers__, verify=False)
                    __response__.raise_for_status()
                    if "smAppInstance" in __response__.json():
                        for instance in __response__.json()['smAppInstance']:
                            if "enabled" in instance['adminState']:
                                __info__['fw_instances_used'] = __info__['fw_instances_used'] + 1
                                logger.debug("Return smAppInstance for {0}, lets look at resourceProfileName = {1}".format(fxo,instance['resourceProfileName']))
                                if 'mall' in instance['resourceProfileName'].lower():
                                    logger.debug("found small for {0} 01".format(fxo))
                                    __info__['fw_small_used'] = __info__['fw_small_used'] + 1
                                    __info__['fw_cpu_available'] = __info__['fw_cpu_available'] - self.fxos_info['fxos_small_cost']
                                    logger.debug("found small for {0} 02".format(fxo))
                                elif 'edium' in instance['resourceProfileName'].lower():
                                    __info__['fw_medium_used'] = __info__['fw_medium_used'] + 1
                                    __info__['fw_cpu_available'] = __info__['fw_cpu_available'] - self.fxos_info['fxos_medium_cost']
                                elif 'xlarge' in instance['resourceProfileName'].lower() or "ery" in instance['resourceProfileName'].lower():
                                    __info__['fw_large_used'] = __info__['fw_large_used'] + 1
                                    __info__['fw_cpu_available'] = __info__['fw_cpu_available'] - self.fxos_info['fxos_large_cost']
                                elif 'large' in instance['resourceProfileName'].lower() and "ery" not in instance['resourceProfileName'].lower():
                                    __info__['fw_xllarge_used'] = __info__['fw_xllarge_used'] + 1
                                    __info__['fw_cpu_available'] = __info__['fw_cpu_available'] - self.fxos_info['fxos_xllarge_cost']
                    # Now we need to calculate how many available cpu remains and the available FW contexts
                    logger.debug("How many cpu do we have left on {0}? {1} ".format(fxo,__info__['fw_cpu_available']))
                    __info__['fw_small_available'] = math.trunc(__info__['fw_cpu_available']/self.fxos_info['fxos_small_cost'])
                    __info__['fw_medium_available'] = math.trunc(__info__['fw_cpu_available'] / self.fxos_info['fxos_medium_cost'])
                    __info__['fw_large_available'] = math.trunc(__info__['fw_cpu_available'] / self.fxos_info['fxos_large_cost'])
                    __info__['fw_xllarge_available'] = math.trunc(__info__['fw_cpu_available'] / self.fxos_info['fxos_large_cost'])
                    logger.debug("{0} - return {1}".format(fxo,__info__))
                    return(__info__)
                except HTTPError as http_err:
                    logging.error('{0}'.format(http_err))
                except Exception as err:
                    logging.error('{0}'.format(err))
        except Exception as err:
            logging.error('{0}'.format(err))
            return

    def fxos_update(self):
        try:
            '''
                Workflow 
                1. Test Login
                2. Pull information from each FXO instance
            '''
            __loging_status__ = 0  #0=nologin 1=login_success
            try:
                __headers__ = {
                    'username': self.fxos_info['username'],
                    'password': self.fxos_info['password']
                }
                __login_test__ = session.request("POST",'https://{0}/api/login'.format(self.fxos_info['fxos'][0]),headers=__headers__,verify=False)
                __login_test__.raise_for_status()
                if "token" in __login_test__.json():
                    logger.info("Successfully logged into devices")
                    __loging_status__ = 1
                else:
                    raise Exception("200 Login but without a token.. Not going to work")
            except HTTPError as http_err:
                logging.error('{0}'.format(http_err))
            except Exception as err:
                logging.error('{0}'.format(err))
            # IF initial login was successful then we can do the rest.
            if __loging_status__ == 1:
                try:
                    ## Clear out previous information
                    self.fxo_totals = {}
                    with ThreadPoolExecutor(max_workers=13) as executor:
                        futures = [executor.submit(self.fxo_pull,fxo) for fxo in self.fxos_info['fxos']]
                    try:
                        for fxo in as_completed(futures,timeout=30):
                            self.fxo_totals['{0}'.format(fxo.result()['name'])] = fxo.result()
                        logger.debug("totals = {0}".format(self.fxo_totals))
                    except TimeoutError as err:
                        logging.error('Threading error : {0}'.format(err))
                    except Exception as err:
                        logging.error('Threading error : {0}'.format(err))
                except Exception as err:
                    logging.error('{0}'.format(err))
        except:
            logger.error("Failure in fxos_update")
        return("{0}".format(self.fxos_info['counter'] ))

class aci_functions:
    def __init__(self):
        self.version = '1.0'
        self.aci_info = {
            'apic': ['10.101.0.30', '10.101.0.33', '10.102.0.30', '10.102.0.33','10.112.66.4'],
            'cisco_apic': ['10.101.0.30', '10.101.0.33', '10.102.0.30', '10.102.0.33'],
            'hcs_apic':['10.112.66.4'],
            'hcs_username': os.environ.get('HCS_ADMIN_USER'),
            'hcs_password': os.environ.get('HCS_ADMIN_PWD'),
            'username': os.environ.get('USER_NAME'),
            'password': os.environ.get('PASSWORD'),
            'counter': 1,
            'notes': 'Report Time:' + str(now),
            'title': 'Data Center Available Ports (ACI)',
            'title2': 'Customer POD',
            'title3': 'Operations POD',
            'title4': 'Amsterdam POD'
        }
        self.aci_totals = {}

    def aci_status(self):
        return(self.aci_totals)

    def aci_pull(self,apic):
        try:
            logger.debug("Working on {0}".format(apic))
            hostname = socket.gethostbyaddr(apic)[0].split("-")[0].upper()
            __info__ = {
                        'ip': apic,
                        'name': '{0}'.format(hostname.split("-")[0]),
                        'region': hostname[:2],
                        'datacenter': hostname[2:5],
                        'controller-id':"",
                        'nodes_cust': {},
                        'nodes_ops': {},
                        'nodes_ams': {},
                        'id': ''
                        }
            # Login to get Token
            try:
                __method__ = '/api/aaaLogin.json'
                __data__ = {'aaaUser': {'attributes': {'name': self.aci_info['username'], 'pwd': self.aci_info['password']}}}
                __data_hcs__ = {'aaaUser': {'attributes': {'name': self.aci_info['hcs_username'], 'pwd': self.aci_info['hcs_password']}}}
                login_data = json.dumps(__data__)
                login_hcs_data = json.dumps(__data_hcs__)
                if '10.112' in apic:
                    __response__ = session.request("POST", 'https://{0}{1}'.format(apic, __method__), data=login_hcs_data,verify=False)
                    __response__.raise_for_status()
                    __response_auth__ = __response__.json()
                    login_attributes = __response_auth__['imdata'][0]['aaaLogin']['attributes']
                else:
                    __response__ = session.request("POST", 'https://{0}{1}'.format(apic, __method__), data=login_data,verify=False)
                    __response__.raise_for_status()
                    __response_auth__ = __response__.json()
                    login_attributes = __response_auth__['imdata'][0]['aaaLogin']['attributes']
                if "token" in login_attributes:
                    #logger.debug(__response__.json())
                    __token__ = {}
                    __token__['APIC-Cookie'] = login_attributes['token']
                else:
                    raise Exception("200 Login but without a token.. Not going to work")
            except HTTPError as http_err:
                logging.error('{0}'.format(http_err))
            except Exception as err:
                logging.error('{0}'.format(err))
            # Pull Information
            if len(login_attributes['token']) >= 1:
                try:
                    #logger.debug("Login Successful lets pull the info for {0}".format(__info__['name']))
                    method_fabric = '/api/node/class/fabricNode.json'
                    __cookies__ = __token__
                    __response_fabric__ = session.request("Get", 'https://{0}{1}'.format(apic, method_fabric), cookies=__cookies__, verify=False)
                    __response_fabric__.raise_for_status()
                    #logger.debug("return - {0}".format(__response_fabric__.json()))
                    for imdata in __response_fabric__.json()['imdata']:
                         #logger.debug("{0} - {1}".format(imdata['fabricNode']['attributes']['id'],imdata['fabricNode']['attributes']['name']))
                         if "controller" not in imdata['fabricNode']['attributes']['role'] and "spine" not in imdata['fabricNode']['attributes']['role']:
                            if '01COR' in imdata['fabricNode']['attributes']['name']:
                                __info__['nodes_ops']['{0}'.format(imdata['fabricNode']['attributes']['name'])] = {
                                'id': '{0}'.format(imdata['fabricNode']['attributes']['id']), 'role': '{0}'.format(imdata['fabricNode']['attributes']['role']),
                                'total_interfaces': '', 'available_interfaces': ''                                                        
                                }
                                id = '{0}'.format(imdata['fabricNode']['attributes']['id'])   
                                method_interfaces = '/api/node/class/topology/pod-1/node-{0}/l1PhysIf.json'.format(id)
                                method_chassis = '/api/node/mo/topology/pod-1/node-{0}/sys/ch.json'.format(id)
                                __response_interfaces__ = session.request("Get", 'https://{0}{1}'.format(apic, method_interfaces), cookies=__cookies__, verify=False)
                                __response_chassis__ = session.request("Get", 'https://{0}{1}'.format(apic, method_chassis), cookies=__cookies__, verify=False)
                                interface_counter = 0
                                used_if = 0
                                for imdata_interface in __response_interfaces__.json()['imdata']:
                                        interface_counter = interface_counter + 1 
                                        if  "enabled" in imdata_interface['l1PhysIf']['attributes']['switchingSt']:
                                            used_if = used_if + 1
                                        if "YC" in __response_chassis__.json()['imdata'][0]['eqptCh']['attributes']['model']:
                                           __info__['nodes_ops']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['type'] = 'Fiber' 
                                        else:
                                            __info__['nodes_ops']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['type'] = 'Copper'
                                __info__['nodes_ops']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['total_interfaces'] = interface_counter
                                __info__['nodes_ops']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['available_interfaces'] = __info__['nodes_ops']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['total_interfaces'] - used_if
                            elif "NLAM" in imdata['fabricNode']['attributes']['name'] and re.search(r'L10[1-4]', imdata['fabricNode']['attributes']['name']):
                                __info__['nodes_ams']['{0}'.format(imdata['fabricNode']['attributes']['name'])] = {
                                'id': '{0}'.format(imdata['fabricNode']['attributes']['id']), 'role': '{0}'.format(imdata['fabricNode']['attributes']['role']),
                                'total_interfaces': '', 'available_interfaces': ''                                                        
                                }
                                id = '{0}'.format(imdata['fabricNode']['attributes']['id'])   
                                method_interfaces = '/api/node/class/topology/pod-1/node-{0}/l1PhysIf.json'.format(id)
                                method_chassis = '/api/node/mo/topology/pod-1/node-{0}/sys/ch.json'.format(id)
                                __response_interfaces__ = session.request("Get", 'https://{0}{1}'.format(apic, method_interfaces), cookies=__cookies__, verify=False)
                                __response_chassis__ = session.request("Get", 'https://{0}{1}'.format(apic, method_chassis), cookies=__cookies__, verify=False)
                                interface_counter = 0
                                used_if = 0
                                for imdata_interface in __response_interfaces__.json()['imdata']:
                                        interface_counter = interface_counter + 1 
                                        if  "enabled" in imdata_interface['l1PhysIf']['attributes']['switchingSt']:
                                            used_if = used_if + 1
                                        if "YC" in __response_chassis__.json()['imdata'][0]['eqptCh']['attributes']['model']:
                                           __info__['nodes_ams']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['type'] = 'Fiber' 
                                        else:
                                            __info__['nodes_ams']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['type'] = 'Copper'
                                        __info__['nodes_ams']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['total_interfaces'] = interface_counter
                                        __info__['nodes_ams']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['available_interfaces'] = __info__['nodes_ams']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['total_interfaces'] - used_if
                            elif "controller" not in imdata['fabricNode']['attributes']['role'] and "spine" not in imdata['fabricNode']['attributes']['role'] and '02COR' in imdata['fabricNode']['attributes']['name']:
                                __info__['nodes_cust']['{0}'.format(imdata['fabricNode']['attributes']['name'])] = {
                                'id': '{0}'.format(imdata['fabricNode']['attributes']['id']), 'role': '{0}'.format(imdata['fabricNode']['attributes']['role']),
                                'total_interfaces': '', 'available_interfaces': ''                                                        
                                }
                                id = '{0}'.format(imdata['fabricNode']['attributes']['id'])   
                                method_interfaces = '/api/node/class/topology/pod-1/node-{0}/l1PhysIf.json'.format(id)
                                method_chassis = '/api/node/mo/topology/pod-1/node-{0}/sys/ch.json'.format(id)
                                __response_interfaces__ = session.request("Get", 'https://{0}{1}'.format(apic, method_interfaces), cookies=__cookies__, verify=False)
                                __response_chassis__ = session.request("Get", 'https://{0}{1}'.format(apic, method_chassis), cookies=__cookies__, verify=False)
                                interface_counter = 0
                                used_if = 0
                                for imdata_interface in __response_interfaces__.json()['imdata']:
                                        interface_counter = interface_counter + 1 
                                        if  "enabled" in imdata_interface['l1PhysIf']['attributes']['switchingSt']:
                                            used_if = used_if + 1
                                        if "YC" in __response_chassis__.json()['imdata'][0]['eqptCh']['attributes']['model']:
                                            __info__['nodes_cust']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['type'] = 'Fiber' 
                                        else:
                                            __info__['nodes_cust']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['type'] = 'Copper'
                                __info__['nodes_cust']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['total_interfaces'] = interface_counter
                                __info__['nodes_cust']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['available_interfaces'] = __info__['nodes_cust']['{0}'.format(imdata['fabricNode']['attributes']['name'])]['total_interfaces'] - used_if
                    return(__info__)
                except HTTPError as http_err:
                    logging.error('{0}'.format(http_err))
                except Exception as err:
                    logging.error('{0}'.format(err))
        except Exception as err:
            logging.error('{0}'.format(err))
            return

    def aci_update(self):
        try:
            '''
                Workflow 
                1. Test Login
                2. Pull information from each aci instance
            '''
            __loging_status__ = 0  #0=nologin 1=login_success
            try:
                __data__ = {'aaaUser': {'attributes': {'name': os.environ.get('USER_NAME'), 'pwd': os.environ.get('PASSWORD')}}}
                __data_hcs__ = {'aaaUser': {'attributes': {'name': os.environ.get('HCS_ADMIN_USER'), 'pwd': os.environ.get('HCS_ADMIN_PWD')}}}
                login_data = json.dumps(__data__)
                login_hcs_data = json.dumps(__data_hcs__)
                __login_test__ = session.request("POST",'https://{0}/api/aaaLogin.json'.format(self.aci_info['cisco_apic'][0]),data=login_data,verify=False)
                __login_hcs_test__ = session.request("POST",'https://{0}/api/aaaLogin.json'.format(self.aci_info['hcs_apic'][0]),data=login_hcs_data,verify=False)
                __login_test__.raise_for_status()
                __login_hcs_test__.raise_for_status()
                __login_auth__ = __login_test__.json()
                __login_hcs_auth__ = __login_hcs_test__.json()
                login_attributes = __login_auth__['imdata'][0]['aaaLogin']['attributes']
                login_hcs_attributes = __login_hcs_auth__['imdata'][0]['aaaLogin']['attributes']
                if "token" in login_attributes and login_hcs_attributes:
                    logger.info("Successfully logged into devices")
                    __loging_status__ = 1
                else:
                    raise Exception("200 Login but without a token.. Not going to work")
            except HTTPError as http_err:
                logging.error('{0}'.format(http_err))
            except Exception as err:
                logging.error('{0}'.format(err))
            # IF initial login was successful then we can do the rest.
            if __loging_status__ == 1:
                try:
                    ## Clear out previous information
                    self.aci_totals = {}
                    with ThreadPoolExecutor(max_workers=13) as executor:
                        futures = [executor.submit(self.aci_pull,apic) for apic in self.aci_info['apic']]
                    try:
                        for apic in as_completed(futures,timeout=30):
                            self.aci_totals['{0}'.format(apic.result()['name'])] = apic.result()
                        #logger.debug("totals = {0}".format(self.aci_totals))
                    except TimeoutError as err:
                        logging.error('Threading error : {0}'.format(err))
                    except Exception as err:
                        logging.error('Threading error : {0}'.format(err))
                except Exception as err:
                    logging.error('{0}'.format(err))
        except:
            logger.error("Failure in aci_update")
        return("{0}".format(self.aci_info['counter'] ))

class license_functions():
    def __init__(self):
        self.version = '1.0'
        self.license_info = {
            'license_server': ['10.101.64.27'],
            'notes': 'Report Time:  ' + str(now),
            'authorization': os.environ.get('IOSXE_BASIC_AUTH'),
            'counter': 1,            
            'title': 'Licensing Dashboard',
            'title2': 'Cisco Smart Licensing',
            'title3': 'EM7 Licensing',
            'title4': ''
    }
        self.license_totals = {}
        
    def license_status(self):
        return(self.license_totals)

    def license_pull(self, license_server):
        try:
            #logger.debug("Working on {0}".format(license_server))
            #hostname = socket.gethostbyaddr(license_server)[0].split("-")[0].upper()
            __info__ = {
                        'ip': license_server,
                        'CSSM': {},
                        'EM7': {}
                    }
             # Pull Information EM7
            try:
                logger.debug("Login Successful lets pull the info for {0}".format('EM7'))
                method_total = '/api/appliance/3'
                method_count = '/api/device?limit=100'
                headers = {
                    'Accept': 'application/json',
                    'Authorization': self.license_info['authorization']
                }
                __response_total__ = session.request('Get', 'https://{0}{1}'.format(license_server, method_total), headers=headers, verify=False)
                __response_count__ = session.request('Get', 'https://{0}{1}'.format(license_server, method_count), headers=headers, verify=False)
                __license_total__ =__response_total__.json()
                __license_count__ =__response_count__.json()
                __info__['EM7']['total_license'] = __license_total__['capacity']
                __info__['EM7']['consumed_license'] = __license_count__['total_matched']
                # Pull Information Cisco Smart Licensing
                path = (r'C:\Users\equiros\Documents\Capacity Automation\Capacity App\Capacity_App\licensing\License_Report.xls')
                excel_data = pandas.read_excel(path)
                json_str = excel_data.to_json(orient='records')
                json_py = json.loads(json_str)
                __info__['CSSM'] = json_py
                return(__info__)
            except HTTPError as http_err:
                logging.error('{0}'.format(http_err))
            except Exception as err:
                logging.error('{0}'.format(err))
        except Exception as err:
            logging.error('{0}'.format(err))
            return

    def license_update(self):
        try:
            '''
                Workflow 
                1. Test Login
                2. Pull information from each WAN instance
            '''
            __loging_status__ = 0  #0=nologin 1=login_success
            try:
                method = '/api/appliance/3'
                headers = {
                    'Accept': 'application/json',
                    'Authorization': self.license_info['authorization']
                }
                __login_test__ = session.request('Get','https://{0}{1}'.format(self.license_info['license_server'][0], method), headers=headers, verify=False)
                __login_test__.raise_for_status()
                __login_auth__ = __login_test__.json()
                if "type" in __login_auth__:
                    logger.info("Successfully logged into devices")
                    __loging_status__ = 1
                else:
                    raise Exception("Login Failure. Not going to work")
            except HTTPError as http_err:
                logging.error('{0}'.format(http_err))
            except Exception as err:
                logging.error('{0}'.format(err))
            # IF initial login was successful then we can do the rest.
            if __loging_status__ == 1:
                try:
                    ## Clear out previous information
                    self.license_totals = {}
                    with ThreadPoolExecutor(max_workers=13) as executor:
                        futures = [executor.submit(self.license_pull,license) for license in self.license_info['license_server']]
                    try:
                        for license in as_completed(futures,timeout=30):
                            self.license_totals['{0}'.format(license.result()['ip'])] = license.result()
                        logger.debug("totals = {0}".format(self.license_totals))
                    except TimeoutError as err:
                        logging.error('Threading error : {0}'.format(err))
                    except Exception as err:
                        logging.error('Threading error : {0}'.format(err))
                except Exception as err:
                    logging.error('{0}'.format(err))
        except:
            logger.error("Failure in wan_update")
        return("{0}".format(self.license_info['counter'] ))


class wan_functions():
    def __init__(self):
        self.version = '1.0'
        self.wan_info = {
            'wan_router': ['10.101.3.17', '10.101.3.18', '10.102.3.17', '10.102.3.18'],
            'authorization': os.environ.get('IOSXE_BASIC_AUTH'),
            'notes': 'Report Time:  ' + str(now),
            'counter': 1,
            'title': 'WAN Router Available Ports',
            'title2': 'Public Routers',
            'title3': 'Private Routers',
            'title4': 'INET Routers'
        }
        self.wan_totals = {}

    def wan_status(self):
        return(self.wan_totals)

    def wan_pull(self,wan_router):
        try:
            #logger.debug("Working on {0}".format(wan_router))
            hostname = socket.gethostbyaddr(wan_router)[0].split("-")[0].upper()
            __info__ = {
                        'ip': wan_router,
                        'name': '{0}'.format(hostname.split("-")[0]),
                        'region': hostname[:2],
                        'datacenter': hostname[2:5],
                        'public_router': {'total_interfaces': 0, 'available_interfaces': 0},
                        'private_router': {'total_interfaces': 0, 'available_interfaces': 0},
                        'inet_router': {'total_interfaces': 0, 'available_interfaces': 0},
						'total_interfaces': 0,
                        'available_interfaces': 0
                        }
            # Pull Information
            try:
                logger.debug("Login Successful lets pull the info for {0}".format(__info__['name']))
                method = '/restconf/data/openconfig-interfaces:interfaces'
                headers = {
                    'Accept': 'application/yang-data+json',
                    'Authorization': self.wan_info['authorization']
                }
                __response_interfaces__ = session.request('Get', 'https://{0}{1}'.format(wan_router, method), headers=headers, verify=False)
                __wan_interfaces__ = __response_interfaces__.json()
                if "BPNRTR" in __info__['name']: 
                    for interface in __wan_interfaces__["openconfig-interfaces:interfaces"]['interface']:
                        if "Ethernet" in interface['name']:
                            __info__['public_router']['total_interfaces'] = __info__['public_router']['total_interfaces'] + 1
                        if "Ethernet" in interface['name'] and "LOWER_LAYER_DOWN" in interface['state']['oper-status']:
                            __info__['public_router']['available_interfaces'] = __info__['public_router']['available_interfaces'] + 1
                            __info__['public_router']['name'] = __info__['name']
                elif "PRIRTR" in __info__['name']: 
                    for interface in __wan_interfaces__["openconfig-interfaces:interfaces"]['interface']:
                        if "Ethernet" in interface['name']:
                            __info__['private_router']['total_interfaces'] = __info__['private_router']['total_interfaces'] + 1
                        if "Ethernet" in interface['name'] and "LOWER_LAYER_DOWN" in interface['state']['oper-status']:
                            __info__['private_router']['available_interfaces'] = __info__['private_router']['available_interfaces'] + 1
                            __info__['private_router']['name'] = __info__['name']
                return(__info__)
            except HTTPError as http_err:
                logging.error('{0}'.format(http_err))
            except Exception as err:
                logging.error('{0}'.format(err))
        except Exception as err:
            logging.error('{0}'.format(err))
            return

    def wan_update(self):
        try:
            '''
                Workflow 
                1. Test Login
                2. Pull information from each WAN instance
            '''
            __loging_status__ = 0  #0=nologin 1=login_success
            try:
                method = '/restconf/data/openconfig-interfaces:interfaces'
                headers = {
                    'Accept': 'application/yang-data+json',
                    'Authorization': self.wan_info['authorization']
                }
                __login_test__ = session.request('Get','https://{0}{1}'.format(self.wan_info['wan_router'][0], method), headers=headers, verify=False)
                __login_test__.raise_for_status()
                __login_auth__ = __login_test__.json()
                if "interface" in __login_auth__['openconfig-interfaces:interfaces']:
                    logger.info("Successfully logged into devices")
                    __loging_status__ = 1
                else:
                    raise Exception("Login Failure. Not going to work")
            except HTTPError as http_err:
                logging.error('{0}'.format(http_err))
            except Exception as err:
                logging.error('{0}'.format(err))
            # IF initial login was successful then we can do the rest.
            if __loging_status__ == 1:
                try:
                    ## Clear out previous information
                    self.wan_totals = {}
                    with ThreadPoolExecutor(max_workers=13) as executor:
                        futures = [executor.submit(self.wan_pull,wan) for wan in self.wan_info['wan_router']]
                    try:
                        for wan in as_completed(futures,timeout=30):
                            self.wan_totals['{0}'.format(wan.result()['name'])] = wan.result()
                        logger.debug("totals = {0}".format(self.wan_totals))
                    except TimeoutError as err:
                        logging.error('Threading error : {0}'.format(err))
                    except Exception as err:
                        logging.error('Threading error : {0}'.format(err))
                except Exception as err:
                    logging.error('{0}'.format(err))
        except:
            logger.error("Failure in wan_update")
        return("{0}".format(self.wan_info['counter'] ))

''' 
    API 
'''
# Add classes
fxos_fun = fxos_functions()
aci_fun = aci_functions()
license_fun = license_functions()
wan_fun = wan_functions()

# Test Site
@app.route('/<unbuilt>', methods=['GET'])
def api_unbuilt(unbuilt):
    return("{0} Successful".format(unbuilt))

# FXOS Display sites
@app.route('/fxos', methods=['GET'])
def api_fxos():
    logger.debug("{0}".format(fxos_fun.fxo_status()))
    return render_template('fxos_base.html', fxos=fxos_fun.fxo_status(),info=fxos_fun.fxos_info)

# FXOS Update API
@api.route("/fxos_update")
class fxos(Resource):
    @api.doc('Get FXOS Information')
    def post(self):
        text = fxos_fun.fxos_update()
        return ("{0} {1} Successful --- {2}".format("fxos_update", text, fxos_fun.fxo_status()))

# ACI Display sites
@app.route('/aci', methods=['GET'])
def api_aci():
    logger.debug("{0}".format(aci_fun.aci_status()))
    return render_template('aci_base.html', aci=aci_fun.aci_status(),info=aci_fun.aci_info)

# ACI Update API
@api.route("/aci_update")
class fxos(Resource):
    @api.doc('Get ACI Information')
    def post(self):
        text = aci_fun.aci_update()
        return ("{0} {1} Successful --- {2}".format("aci_update", text, aci_fun.aci_status()))

# WAN Update API
@api.route("/wan_update")
class wan(Resource):
    @api.doc('Get WAN ports Information')
    def post(self):
        text = wan_fun.wan_update()
        return ("{0} {1} Successful --- {2}".format("wan_update", text, wan_fun.wan_status())) 

# WAN Display sites
@app.route('/wan', methods=['GET'])
def api_wan():
    logger.debug("{0}".format(wan_fun.wan_status()))
    return render_template('wan_base.html', wan=wan_fun.wan_status(),info=wan_fun.wan_info)

# Licence Display sites
@app.route('/license', methods=['GET'])
def api_license():
    logger.debug("{0}".format(license_fun.license_status()))
    return render_template('license_base.html', license=license_fun.license_status(),info=license_fun.license_info)

# License Update API
@api.route("/license_update")
class license(Resource):
    @api.doc('Get Licencing Information')
    def post(self):
        text = license_fun.license_update()
        return ("{0} {1} Successful --- {2}".format("license_update", text, license_fun.license_status()))


'''
--------------------------------------------------------------------------------------------------------------------------------------------------------
Main Web-Server
'''
if __name__ == '__main__':
    #webbrowser.get("firefox").open("http://127.0.0.1:5999", new=0)
    print("------------------NOTICE---------------------------------")
    print("     Please open a web browser to the below URL          ")
    print("         HTTP://127.0.0.1:8443                           ")
    print("                                                         ")
    print("Currently only FireFox and Chrome are supported browsers.")
    print("------------------NOTICE---------------------------------")
    app.run(host="0.0.0.0",port=int("8443"), debug=False)


