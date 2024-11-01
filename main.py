import socket

import requests, urllib3, os
from datetime import datetime
from requests.exceptions import HTTPError
from requests.auth import HTTPBasicAuth
from time import process_time, sleep
import logging
# 'fxos': ['10.101.0.16','10.101.0.17','10.101.0.18','10.101.0.19','10.102.0.16','10.102.0.17','10.102.0.18','10.102.0.19']

## Logger setup
logger = logging.getLogger("fxos_pull")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Global Request Session
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
s = requests.session()


def fxo_login(__fxo__, __info__):
    try:
        logger.debug("{0}".format("Login for {0}".format(__fxo__)))
        method = '/api/login'
        headers = {'username': __info__['usr'],
                   'password': __info__['pwd']}
        __response__ = s.request("POST",'https://{0}{1}'.format(__fxo__,method),headers=headers,verify=False)
        __response__.raise_for_status()
        if "token" in __response__.json():
            logger.debug(__response__.json())
            __token__ = __response__.json()['token']
            return(__token__)
        else:
            raise Exception("200 Login but without a token.. Not going to work")
    except HTTPError as http_err:
        logging.error('{0}'.format(http_err))
    except Exception as err:
        logging.error('{0}'.format(err))
    return()

def fxo_smAppInstance(__fxo__, __info__,__token__):
    try:
        logger.debug("{0}".format("Collecting information from {0}".format(__fxo__)))
        total_fxo = {
            'name': '',
            'total_cors': 86,
            'total_cors_used': 0,
            'total': 0,
            'small': 0,
            'medium': 0,
            'large': 0,
            'xlarge': 0
        }
        # Pull Hostname
        # Look up the Hostname to IP address
        try:
            logger.debug(__fxo__)
            hostname = socket.gethostbyaddr(__fxo__)[0]
            total_fxo['name'] = hostname.split("-")[0]
        except:
            logger.error("fxo name lookup failed")
            total_fxo['name'] = __fxo__
        # Lets pull the current smAppInstance
        method = '/api?classId=smAppInstance'
        header = {'token': __token__}
        __response__ = s.request("Get",'https://{0}{1}'.format(__fxo__,method),headers=header,verify=False)
        __response__.raise_for_status()
        if "smAppInstance" in __response__.json():
            for instance in __response__.json()['smAppInstance']:
                if "enabled" in instance['adminState']:
                    total_fxo['total'] = total_fxo['total'] + 1
                    logger.debug("{0}".format(instance['resourceProfileName']))
                    if 'mall' in instance['resourceProfileName'].lower():
                        total_fxo['small'] = total_fxo['small'] + 1
                        total_fxo['total_cors_used'] = total_fxo['total_cors_used'] + 6
                    elif 'edium' in instance['resourceProfileName'].lower():
                        total_fxo['medium'] = total_fxo['medium'] + 1
                        total_fxo['total_cors_used'] = total_fxo['total_cors_used'] + 12
                    elif 'xlarge' in instance['resourceProfileName'].lower() or "ery" in instance['resourceProfileName'].lower():
                        total_fxo['xlarge'] = total_fxo['xlarge'] + 1
                        total_fxo['total_cors_used'] = total_fxo['total_cors_used'] + 18
                    elif 'large' in instance['resourceProfileName'].lower() and "ery" not in instance['resourceProfileName'].lower():
                        total_fxo['large'] = total_fxo['large'] + 1
                        total_fxo['total_cors_used'] = total_fxo['total_cors_used'] + 24
        return(total_fxo)
    except HTTPError as http_err:
        logging.error('{0}'.format(http_err))
    except Exception as err:
        logging.error('{0}'.format(err))
    return ()

def fxo_html(__total_info__):
    ''' Create a file with HTML '''
    logger.debug("Start fxo_html generation")
    now = datetime.now()
    filename = 'fxo_report_{0}.html'.format(now.strftime("%m-%d-%Y"))
    with open(os.path.join(os.getcwd(),filename), 'w') as file:
        html_part_1 = "{0}".format('<!DOCTYPE html><html><head><title>WxCCE Tenant Firewall Capacity</title></head><body><h1></h1></body><style type="text/css">.tg  {border-collapse:collapse;border-color:#9ABAD9;border-spacing:0;border-style:solid;border-width:1px;}.tg td{background-color:#EBF5FF;border-color:#9ABAD9;border-style:solid;border-width:0px;color:#444;font-family:Arial, sans-serif;font-size:14px;overflow:hidden;padding:10px 5px;word-break:normal;}.tg th{background-color:#409cff;border-color:#9ABAD9;border-style:solid;border-width:0px;color:#fff;font-family:Arial, sans-serif;font-size:14px;font-weight:normal;overflow:hidden;padding:10px 5px;word-break:normal;}.tg .tg-qxll{background-color:#9aff99;border-color:#000000;color:#000000;font-family:Arial, Helvetica, sans-serif !important;font-size:18px;text-align:center;vertical-align:middle}.tg .tg-4igb{background-color:#ffffff;border-color:#000000;color:#000000;font-family:Verdana, Geneva, sans-serif !important;font-size:15px;text-align:center;vertical-align:top}.tg .tg-ebbs{background-color:#fffc9e;border-color:#000000;color:#000000;font-family:Arial, Helvetica, sans-serif !important;font-size:18px;text-align:center;vertical-align:middle}.tg .tg-mty9{background-color:#9b9b9b;border-color:inherit;color:#ffffff;font-family:Verdana, Geneva, sans-serif !important;font-size:15px;font-weight:bold;text-align:center;vertical-align:top}.tg .tg-9dcl{background-color:#ffccc9;border-color:#000000;color:#000000;font-family:Arial, Helvetica, sans-serif !important;font-size:18px;text-align:center;vertical-align:middle}.tg .tg-za0i{background-color:#efefef;border-color:#000000;color:#000000;font-family:Verdana, Geneva, sans-serif !important;font-size:15px;text-align:center;vertical-align:top}</style><table class="tg" style="undefined;table-layout: fixed; width: 462px"><colgroup><col style="width: 169px"><col style="width: 70px"><col style="width: 82px"><col style="width: 67px"><col style="width: 74px"></colgroup>')
        html_part_2 = "{0}".format('<thead><tr><th class="tg-mty9">Firewall</th><th class="tg-mty9">Small</th><th class="tg-mty9">Medium</th><th class="tg-mty9">Large</th><th class="tg-mty9">XLarge</th></tr></thead><tbody>')
        html_part_3 = ""
        html_part_4 = "{0}".format('</tbody></table><font size="2" face="Verdana" color="black"><p>Even tenant example: wx002</p><font size="2" face="Verdana" color="black"><p>Odd tenant example: wx005</p></html>')
        for fxo in __total_info__:
            logger.debug("Name = {0}".format(__total_info__[fxo]['name']))
            part_3 = ('<tr><td class="tg-4igb">{0}</td><td class="tg-ebbs">{1}</td><td class="tg-ebbs">{2}</td><td class="tg-9dcl">{3}</td><td class="tg-9dcl">{4}</td></tr>'.format(__total_info__[fxo]['name'],__total_info__[fxo]['small'],__total_info__[fxo]['medium'],__total_info__[fxo]['large'],__total_info__[fxo]['xlarge']))
            html_part_3 = html_part_3 + part_3
        file_write_output = "{0}{1}{2}{3}".format(html_part_1,html_part_2,html_part_3,html_part_4)
        file.write("{0}".format(file_write_output))
        file.close()

if __name__ == "__main__":
    __info__={
        'usr': 'equiros-a',
        'pwd': 'esqu!r0s2121213',
        'fxos': ['10.101.0.16','10.101.0.18','10.101.0.17','10.101.0.19','10.102.0.16','10.102.0.18','10.102.0.17','10.102.0.19']
        }
    __total_info__ = {}
    for fxo in __info__['fxos']:
        # Used for development
        __token__ = fxo_login(fxo, __info__)
        if len(__token__) >= 1:
            total_fxo = fxo_smAppInstance(fxo, __info__,__token__)
            logger.info("{0} has {1}".format(fxo, total_fxo))
            __total_info__[fxo] = total_fxo
        else:
            logger.error("Login for {0} did NOT return a token".format(fxo))
    logger.info("{0}".format(__total_info__))
    fxo_html(__total_info__)
