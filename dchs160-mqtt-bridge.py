#!/usr/bin/python3
#
# Read data from D-Link Water sensor.
#
# pip3 install paho-mqtt tendo
#
#
# To run in crontab, do the same again as root
# sudo su -
# pip3 install paho-mqtt tendo
#
#
# CRONTAB:
# @reboot sleep 60;sudo --user=pi /home/pi/dchs160-mqtt-bridge/dchs160-mqtt-bridge.py
# 0 * * * * sudo --user=pi /home/pi/dchs160-mqtt-bridge/dchs160-mqtt-bridge.py
#

import re, requests, sys, os, logging, socket, argparse
import json, time, xml, hmac, urllib, asyncio, functools, aiohttp, xmltodict
import xml.etree.ElementTree as ET
import paho.mqtt.client as paho
from tendo import singleton
from logging.handlers import RotatingFileHandler
from io import BytesIO
from datetime import datetime, timedelta
from shutil import copyfile

try:
    from ConfigParser import RawConfigParser
except ImportError as e:
    from configparser import RawConfigParser

config = {}

# -------------------- LoadConfig -----------------------------------
def LoadConfig(conf_file):
    global config

    try:
        configParser = RawConfigParser()
        configParser.read(conf_file)
    except Exception as e1:
        logger.critical("Error in LoadConfig: " + str(e1))
        return False

    parameters = {'DebugLevel': str, 'MQTT_Server': str, 'MQTT_Port': int, 'MQTT_User': str, 'MQTT_Password': str, 'DCH_Server': str, 'DCH_Password': int, 'EnableDiscovery': bool}
    for key, type in parameters.items():
        try:
            if configParser.has_option("General", key):
                config[key] = ReadValue(key, return_type=type, section="General", configParser=configParser)
        except Exception as e1:
            logger.critical("Missing config file or config file entries in Section General for key "+key+": " + str(e1))
            return False

    return True

def ReadValue(Entry, return_type = str, default = None, section = None, NoLog = False, configParser = None):
    try:
        if configParser.has_option(section, Entry):
            if return_type == str:
                return configParser.get(section, Entry)
            elif return_type == bool:
                return configParser.getboolean(section, Entry)
            elif return_type == float:
                return configParser.getfloat(section, Entry)
            elif return_type == int:
                return configParser.getint(section, Entry)
            else:
                logger.error("Error in MyConfig:ReadValue: invalid type:" + str(return_type))
                return default
        else:
            return default
    except Exception as e1:
        if not NoLog:
            logger.critical("Error in MyConfig:ReadValue: " + Entry + ": " + str(e1))
        return default

# -------------------- Handle Messages -----------------------------------

def haState(result, isWater):
    if (result == "OK") and (isWater == "true"):
       return "ALARM"
    elif (result != "OK"):
       return "ERROR"
    else:
       return "OK"

def sendMQTT(t, ID, status):
    logger.info("PUBLISHING to MQTT: home/dlink/sensor/state/"+str(ID)+" = " + status)
    t.publish("home/dlink/sensor/state/"+str(ID),status,retain=True)
    
def sendMQTTAttr(t, ID, attr):
    logger.info("PUBLISHING to MQTT: home/dlink/sensor/attributes/"+str(ID)+" = " + json.dumps(attr))
    t.publish("home/dlink/sensor/attributes/"+str(ID),json.dumps(attr))
    
def sendRawMQTT(t, topic, msg):
    logger.info("PUBLISHING to MQTT: " + topic + " = " + msg)
    t.publish(topic,msg,retain=True)

def sendStartupInfo(t, sensorID, sensorName):
    topic = sensorName.lower().replace(" ", "_")
    sendRawMQTT(t, "homeassistant/sensor/"+topic+"/config", '{"name": "'+sensorName+'", "state_topic": "home/dlink/sensor/state/'+str(sensorID)+'", "json_attributes_topic": "home/dlink/sensor/attributes/'+str(sensorID)+'"}')

def on_connect(client, userdata, flags, rc):
    global config

    logger.info("Connected to MQTT with result code "+str(rc))
 

# -------------------- Dlink Connection Classes -----------------------------------

def _hmac(key, message):
    return hmac.new(key.encode('utf-8'),
                    message.encode('utf-8')).hexdigest().upper()


class AuthenticationError(Exception):
    """Thrown when login fails."""

    pass


class HNAPClient:
    """Client for the HNAP protocol."""

    def __init__(self, soap, username, password, logger, loop=None):
        """Initialize a new HNAPClient instance."""
        self.username = username
        self.password = password
        self.logged_in = False
        self.logger = logger
        self.loop = loop or asyncio.get_event_loop()
        self.actions = None
        self._client = soap
        self._private_key = None
        self._cookie = None
        self._auth_token = None
        self._timestamp = None

    @asyncio.coroutine
    def login(self):
        """Authenticate with device and obtain cookie."""
        logger.info('Logging into device')
        self.logged_in = False
        resp = yield from self.call(
            'Login', Action='request', Username=self.username,
            LoginPassword='', Captcha='')

        challenge = resp['Challenge']
        public_key = resp['PublicKey']
        self._cookie = resp['Cookie']
        self.logger.debug('Challenge: %s, Public key: %s, Cookie: %s',
                      challenge, public_key, self._cookie)

        self._private_key = _hmac(public_key + str(self.password), challenge)
        self.logger.debug('Private key: %s', self._private_key)

        try:
            password = _hmac(self._private_key, challenge)
            resp = yield from self.call(
                'Login', Action='login', Username=self.username,
                LoginPassword=password, Captcha='')

            if resp['LoginResult'].lower() != 'success':
                raise AuthenticationError('Incorrect username or password')

            if not self.actions:
                self.actions = yield from self.device_actions()

        except xml.parsers.expat.ExpatError:
            raise AuthenticationError('Bad response from device')

        self.logged_in = True

    @asyncio.coroutine
    def device_actions(self):
        actions = yield from self.call('GetDeviceSettings')
        return list(map(lambda x: x[x.rfind('/')+1:],
                        actions['SOAPActions']['string']))

    @asyncio.coroutine
    def soap_actions(self, module_id):
        return (yield from self.call(
            'GetModuleSOAPActions', ModuleID=module_id))

    @asyncio.coroutine
    def call(self, method, *args, **kwargs):
        """Call an NHAP method (async)."""
        # Do login if no login has been done before
        if not self._private_key and method != 'Login':
            yield from self.login()

        self._update_nauth_token(method)
        try:
            result = yield from self.soap().call(method, **kwargs)
            if 'ERROR' in result:
                self._bad_response()
        except:
            self._bad_response()
        return result

    def _bad_response(self):
        self.logger.error('Got an error, resetting private key')
        self._private_key = None
        raise Exception('got error response from device')

    def _update_nauth_token(self, action):
        """Update NHAP auth token for an action."""
        if not self._private_key:
            return

        self._timestamp = int(datetime.now().timestamp())
        self._auth_token = _hmac(
            self._private_key,
            '{0}"{1}{2}"'.format(self._timestamp, ACTION_BASE_URL, action))
        self.logger.debug('Generated new token for %s: %s (time: %d)',
                      action, self._auth_token, self._timestamp)

    def soap(self):
        """Get SOAP client with updated headers."""
        if self._cookie:
            self._client.headers['Cookie'] = 'uid={0}'.format(self._cookie)
        if self._auth_token:
            self._client.headers['HNAP_AUTH'] = '{0} {1}'.format(
                self._auth_token, self._timestamp)

        return self._client

class NanoSOAPClient:

    BASE_NS = {'xmlns:soap': 'http://schemas.xmlsoap.org/soap/envelope/',
               'xmlns:xsd': 'http://www.w3.org/2001/XMLSchema',
               'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance'}
    ACTION_NS = {'xmlns': 'http://purenetworks.com/HNAP1/'}

    def __init__(self, address, action, logger, loop=None, session=None):
        self.address = 'http://{0}/HNAP1'.format(address)
        self.action = action
        self.logger = logger
        self.loop = loop or asyncio.get_event_loop()
        self.session = session or aiohttp.ClientSession(loop=loop)
        self.headers = {}

    def _generate_request_xml(self, method, **kwargs):
        body = ET.Element('soap:Body')
        action = ET.Element(method, self.ACTION_NS)
        body.append(action)

        for param, value in kwargs.items():
            element = ET.Element(param)
            element.text = str(value)
            action.append(element)

        envelope = ET.Element('soap:Envelope', self.BASE_NS)
        envelope.append(body)

        f = BytesIO()
        tree = ET.ElementTree(envelope)
        tree.write(f, encoding='utf-8', xml_declaration=True)

        return f.getvalue().decode('utf-8')

    @asyncio.coroutine
    def call(self, method, **kwargs):
        xml = self._generate_request_xml(method, **kwargs)

        headers = self.headers.copy()
        headers['SOAPAction'] = '"{0}{1}"'.format(self.action, method)

        self.logger.debug("REQUEST: " + xml)
        resp = yield from self.session.post(
            self.address, data=xml, headers=headers, timeout=10)
        text = yield from resp.text()
        self.logger.debug("RESPONSE: " + text)
        parsed = xmltodict.parse(text)
        if 'soap:Envelope' not in parsed:
            self.logger.error("parsed: " + str(parsed))
            raise Exception('probably a bad response')

        return parsed['soap:Envelope']['soap:Body'][method + 'Response']

# -------------------- Dlink Water Sensor Code -----------------------------------

@asyncio.coroutine
def runWaterSensorCheck(cmd, mqttHandler):
    prevState = ""
    connectionReset = False;
    session = aiohttp.ClientSession()
    soap = NanoSOAPClient(config["DCH_Server"], ACTION_BASE_URL, logger, loop=loop, session=session)
    client = HNAPClient(soap, 'Admin', str(config["DCH_Password"]), logger, loop=loop)
    yield from client.login()

    if cmd == 'actions':
        print('Supported actions:')
        print('\n'.join(client.actions))
    elif cmd == 'log':
        log = yield from motion.system_log()
    elif cmd != '':
        resp = yield from client.call(cmd, ModuleID=1)
        print (cmd+": " + json.dumps(resp, indent=4) + "\n\n")
    else:
        resp1 = yield from client.call("GetDeviceSettings", ModuleID=1)
        resp2 = yield from client.call("GetLatestDetection", ModuleID=1)
        DetectionTime = "No Water Detection Log"
        if resp2["LatestDetectTime"] is not None:
           DetectionTime = datetime.fromtimestamp(int(resp2["LatestDetectTime"])).strftime('%Y-%m-%d %H:%M:%S')

        if config["EnableDiscovery"]:
            sendStartupInfo(mqttHandler, 1, resp1["DeviceName"])
            time.sleep(5) # Let HomeAssistant Catch up
            
        attr = {"ModelDescription": resp1["ModelDescription"], "ModelName": resp1["ModelName"], "FirmwareVersion": resp1["FirmwareVersion"], "LatestFirmwareVersion": resp1["LatestFirmwareVersion"], "DeviceMacId": resp1["DeviceMacId"], "DetectionTime": DetectionTime}    
        sendMQTTAttr(mqttHandler, 1, attr)

        while True:
            if connectionReset:
                try:
                    sendMQTT(mqttHandler, 1, "ERROR")
                    prevState = "ERROR"
                    logger.error("Trying to reconnect...")
                    yield from client.login()
                    connectionReset = False;
                except Exception as e1:
                    logger.error("Reconnect Failed.... "+str(e1))
                    logger.error("Waiting 5 mins before re-try...")
                    connectionReset = True;
                    time.sleep(300)
            else:
                try: 
                    resp = yield from client.call("GetWaterDetectorState", ModuleID=1)
                    state= haState(resp["GetWaterDetectorStateResult"], resp["IsWater"])
                    logger.debug("Got state: "+state)
                    
                    if (state != prevState):
                        sendMQTT(mqttHandler, 1, state)
                        prevState = state
                        logger.info("STATE CHANGED, NEW STATE " + state)
                    # print (cmd+": " + json.dumps(resp, indent=4) + "\n\n")
                    # print (state)
                except Exception as e1:
                    logger.error("got exception: "+str(e1))
                    logger.error("logging in again...")
                    connectionReset = True;
            time.sleep(10)
             
    yield from session.close()
 
if __name__ == '__main__':
    ACTION_BASE_URL = 'http://purenetworks.com/HNAP1/'
    LEVELS = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}
              
    curr_path = os.path.dirname(__file__)
    curr_name = os.path.basename(__file__)
    log_name = curr_name.replace(".py", ".log")
    log_file = curr_path+"/"+log_name
    log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')

    rotatingHandler = RotatingFileHandler(log_file, mode='a', maxBytes=1*1024*1024, backupCount=2, encoding=None, delay=0)
    rotatingHandler.setFormatter(log_formatter)
    rotatingHandler.setLevel(logging.INFO)

    logger = logging.getLogger('root')
    logger.addHandler(rotatingHandler)
    

    # Make sure we are not running already. Otherwise Exit
    try:
       tmp = logging.getLogger().level
       logging.getLogger().setLevel(logging.CRITICAL) # we do not want to see the warning
       me = singleton.SingleInstance() # will sys.exit(-1) if other instance is running
       logging.getLogger().setLevel(tmp)
    except:
       logging.getLogger().setLevel(logging.INFO)
       logger.info("Another instance is already running. quiting...")
       exit()

    # Now read the config file
    parser = argparse.ArgumentParser(description='Dlink DCH-S160 Water Sensor to MQTT Integration for Home Assistant.')
    parser.add_argument('-config', '-c', dest='ConfigFile', default=curr_path+'/dchs160-mqtt-bridge.conf', help='Name of the Config File (incl full Path)')
    parser.add_argument('-address', '-a', dest='DCH_Server', default='dch.local', help='IP Address of the DCH-S160 Water Sensor')
    parser.add_argument('-password', '-p', dest='DCH_Password', help='Password of the DCH-S160 Water Sensor')
    parser.add_argument('-command', '-cmd', dest='cmd', help='Command to be sent to the DCH-S160 Water Sensor')
    args = parser.parse_args()

    if args.ConfigFile == None:
        conf_name = curr_name.replace(".py", ".conf")
        conf_file = curr_path+"/"+conf_name
    else:
        conf_file = args.ConfigFile

    if not os.path.isfile(conf_file):
        logger.info("Creating new config file : " + conf_file)
        defaultConfigFile = curr_path+'/defaultConfig.conf'
        if not os.path.isfile(defaultConfigFile):
            logger.critical("Failure to create new config file: "+defaultConfigFile)
            sys.exit(1)
        else:
            copyfile(defaultConfigFile, conf_file)

    if not LoadConfig(conf_file):
        logger.critical("Failure to load configuration parameters")
        sys.exit(1) 
        
    level = LEVELS.get(config["DebugLevel"], logging.WARNING)
    logging.getLogger().setLevel(level)
    rotatingHandler.setLevel(level)
    
    loop = asyncio.get_event_loop()
    cmd = ""
    t = paho.Client(client_id="dchs160-mqtt-bridge")                           #create client object
    
    if args.DCH_Password != None:
        config["DCH_Server"] = args.DCH_Server
        config["DCH_Password"] = args.DCH_Password
    if args.cmd != None:
        cmd = args.cmd
    else: 
        # And connect to MQTT
        t.username_pw_set(username=config["MQTT_User"],password=config["MQTT_Password"])
        t.connect(config["MQTT_Server"],config["MQTT_Port"])
        t.on_connect = on_connect
        logger.info("Connected to MQTT on "+config["MQTT_Server"]+":"+str(config["MQTT_Port"]))
        
    try:
        loop.run_until_complete(runWaterSensorCheck(cmd, t))
    except KeyboardInterrupt:
        for task in asyncio.Task.all_tasks():
             task.cancel()
             loop.run_forever()
    finally:
        loop.close()

    del me
    
    sys.exit()
    
