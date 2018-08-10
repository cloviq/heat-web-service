from zeep import Client, helpers, xsd
from zeep.plugins import HistoryPlugin
import csv
import os
import base64
import logging
import codecs
from logging import handlers
from Crypto.Cipher import Blowfish
import time
from lxml import etree


history = HistoryPlugin(maxlen=10)

tenantId = 'customer-env'
client = Client('https://url-to-customer.com/ServiceAPI/FRSHEATIntegration.asmx?WSDL', plugins=[history])
factory = client.type_factory('ns0')
#field = factory.FieldClass(Name='IncidentNumber', Type='Decimal')

query_type = client.get_type('ns0:ObjectQueryDefinition')
query = query_type(
                   From={'Object': 'Incident'},
                   Top=2147483646,
                   Distinct=0,
                   PasswordFieldBehavior='Services'
                   )

query.Select = factory.SelectClass(All=False)

fields = {'IncidentNumber': 'Text',
          'ActualCategory': 'Text',
          'ActualService': 'Text',
          'Urgency': 'Text',
          'Category': 'Text',
          'CauseCode': 'Text',
          'CreatedDateTime': 'Text',
          'Impact': 'Text',
          'IsVIP': 'Text',
          'Owner': 'Text',
          'OwnerTeam': 'Text',
          'Priority': 'Text',
          'Resolution': 'Text',
          'Source': 'Text',
          'Service': 'Text',
          'Status': 'Text',
          'Symptom': 'Text',
          'Subcategory': 'Text'}
selectStatement = []
for key, value in fields.items():
    selectStatement.append(factory.FieldClass(Name=key, Type=value))
    #dataFields_array.ObjectCommandDataFieldValue = dataFields_type(Name=key, Value=value)

#selectStatement = factory.FieldClass(Name='IncidentNumber', Type='Text')
#whereStatement = factory.RuleClass(Condition='=', Field='Status', Value='Active', Required=False, ConditionType='ByField')

query.Select.Fields = factory.ArrayOfFieldClass(selectStatement)
#query.Where = factory.ArrayOfRuleClass(whereStatement)

#{'Field': [{'Name': 'IncidentNumber'}, {'Type': 'Text'}]}


def queryResponse():
    result = client.get_type('ns0:ObjectQueryDefinition')
    return result

def AllAllowedObjectNames():
    result = client.service.GetAllAllowedObjectNames(sessionKey, tenantId)
    return result


def GetAllSchemaForObject():
     result = client.service.GetAllSchemaForObject(sessionKey, tenantId, 'Incident#')
     return result

#stands for mobility essentials
def get_mob_essen():
    result = client.service.FindMultipleBusinessObjectsByField(sessionKey, tenantId, 'Incident', 'Status', 'Closed')
    return result

def get_roles():
    result = client.service.GetRolesForUser(sessionKey, tenantId)
    return result


def connect():
    credsFromFile = get_creds()
    userName = credsFromFile[0]
    password = decrypt_password(credsFromFile[1])
    result = client.service.Connect(userName, password, tenantId, 'Sub Administrator')
    return result


def get_users():
    result = client.service.GetUserNames(sessionKey, tenantId, 'A')
    return result

BLOWFISH_KEY = 'ThisIsForDoingCrazyStuffThatYouDontNeedToKnowAbout'


def store_creds():
    userNameI = input('Enter the username: ')
    password = input('Enter the password: ')
    ePassword = encrypt_password(password=password)

    config = open('./webservice.conf', 'w')
    config.write("'")
    config.write(userNameI)
    config.write("'")
    config.write('\n')
    config.write("'")
    config.write(ePassword)
    config.write("'")
    config.close()


# def get_schema():
#     result = client.service.GetSchemaForObject(sessionKey, tenantId, 'Employee#')
#     return result


def decrypt_password(encrypted_pass):
    #This will decrypt a password from a credentialset.
    #:param encrypted_pass:
    #:return:

    encryption_object = Blowfish.new(BLOWFISH_KEY)
    decrypted_pass = str(encryption_object.decrypt(base64.b64decode(encrypted_pass)).decode("utf-8")).rstrip('\00')
    return decrypted_pass


def encrypt_password(password):
    #This will encrypt a password from a credentialset
    #:param password: The un-encrypted password
    #:return: returns the encrypted result

    encryption_object = Blowfish.new(BLOWFISH_KEY)
    padding = 'ThisIsSomePadding'
    if (len(password) % 8) != 0:
        padding = "\00" * (8 - (len(password) % 8))
    encrypted_pass = bytes.decode(base64.b64encode(encryption_object.encrypt(password + padding)))
    return encrypted_pass


def structure(result):
    boList = result.objList.ArrayOfWebServiceBusinessObject
    serResults = helpers.serialize_object(boList)
    resultArray = []
    fieldArr = []
    for itemobject in serResults:
        item = helpers.serialize_object(itemobject)
        info = item['WebServiceBusinessObject']
        for record in info:
            infoDict = {}
            for fieldValues in record['FieldValues']['WebServiceFieldValue']:
                name = fieldValues['Name']
                value = str(fieldValues['Value']).replace(',', ' ')
                infoDict[name] = value
                while name not in fieldArr:
                    fieldArr.append(name)
            resultArray.append(infoDict)
    if not os.path.exists('./output'):
        os.mkdir('./output')
    with codecs.open('./output/heat-results.csv', 'w', 'utf-8') as csvfile:
        recordWriter = csv.DictWriter(csvfile, fieldArr, dialect='excel')
        recordWriter.writeheader()
        for row in resultArray:
            recordWriter.writerow(row)

if not os.path.exists('./webservice.conf'):
    store_creds()


def get_creds():
    dicts_from_file = []
    with open('webservice.conf', 'r') as inf:
        for line in inf:
            dicts_from_file.append(eval(line))
    return dicts_from_file


def log_to_file():
    if not os.path.exists('./heat-logs'):
        os.mkdir('./heat-logs')
    logger = logging.getLogger(__name__)
    hdlr = handlers.RotatingFileHandler('./heat-logs/heat-log.txt', maxBytes=100000, backupCount=10, encoding='UTF-8')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    return logger


logger = log_to_file()


# This is calling the connect function
try:
    proxy = connect()
    logger.info('Connection to HEAT successful.')
except os.error as err:
    logger.error(err)
finally:
    logger.info('Attempted Connection to HEAT.')


sessionKey = proxy.sessionKey

try:
    result = client.service.Search(sessionKey, tenantId, query)
    #print(etree.tounicode(history.last_sent['envelope'], pretty_print=True))
    #print(result)

except os.error as err:
    logger.error(err)
finally:
    logger.info('Attempted to access object names')

# # This function calls the FindMultipleBusinessObjectsByField web service and returns an array of objects
# try:
#     result = get_mob_essen()
#     logger.info('Web Call to FindMultipleBusinessObjectsByField successful.')
# except os.error as err:
#     logger.error(err)
# finally:
#     logger.info('Attempted call to FindMultipleBusinessObjectsByField.')
#
# This is structuring the data and writing to ./output/results.csv


try:
    structure(result)
    logger.info('Results successfully written to ./output/results.csv.')
except os.error as err:
    logger.error(err)
finally:
    logger.info('Attempted to write to csv.')
