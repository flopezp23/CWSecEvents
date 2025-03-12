import requests
import json
from lxml import html
import http.client
import csv
import time


class CloudWAFAPI(object):

  def __init__(self,username,password):
    self.username=username
    self.password=password
    self.tenantID=""
    self.bearerToken=""
    self.oktacookie = None

  def login(self):
    payload = {"username": "automation@radwarecw.com","password": "pic16F877a!","options": {"multiOptionalFactorEnroll": True,"warnBeforePasswordExpired": True}}
    payload["username"] = self.username
    payload["password"] = self.password

    headers = {'Content-Type': 'application/json'}
    data = json.dumps(payload)

    response=requests.request("POST","https://radware-public.okta.com/api/v1/authn",headers=headers, data=data)
    if response.status_code != 200:
      raise Exception("Cannot authenticate to Cloud WAF, invalid credentials")

    responsePayload=response.json()

    ##retrieve tocken and nounce to be used in the authorization request
    sessionToken=responsePayload["sessionToken"]
    nonce=responsePayload["_embedded"]["user"]["id"]

    params = {'client_id': 'M1Bx6MXpRXqsv3M1JKa6','nonce':'','prompt':'none','redirect_uri':'https://portal.radwarecloud.com',
              'response_mode':'form_post','response_type':'token','scope':'api_scope','sessionToken':'','state':'parallel_af0ifjsldkj'}

    params["sessionToken"]=sessionToken
    params["nonce"]=nonce

    ##print("nonce="+nonce)

    ##retrieve the bearerToken to be used for subsequent calls
    response=requests.request("GET","https://radware-public.okta.com/oauth2/aus7ky2d5wXwflK5N1t7/v1/authorize",params=params)
    if response.status_code != 200:
      raise Exception("Not authorized, please make sure you are using a Cloud WAF API account.")

    self.oktacookie=response.cookies

    ###extract bearer token form response
    tree=html.fromstring(response.content)
    self.bearerToken = tree.xpath('//form[@id="appForm"]/input[@name="access_token"]/@value')[0]
    ##print("bearerToken="+self.bearerToken)

    ## Use the bearerToken to retrieve the tenant ID
    headers = {"Authorization": "Bearer %s" % self.bearerToken}

    response=requests.request("GET","https://portal.radwarecloud.com/v1/users/me/summary",headers=headers)
    responsePayload=response.json()

    self.tenantID=responsePayload["tenantEntityId"]

    print("tenantID="+self.tenantID)
    print("login successful")

  def AppList(self):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    headers = {
        'Authorization': 'Bearer ' + self.bearerToken,
        'requestEntityids': self.tenantID,
        'Cookie': 'Authorization=' + self.bearerToken,
        'Content-Type': 'application/json;charset=UTF-8'
      }
    conn.request("GET", "/v1/gms/applications", headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#API Protection

  def getAPIProtection(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"API Security Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    #print(appdata)
    return appdata
#API BLA
  def getAPIBLA(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"API Sequence Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    #print(appdata)
    return appdata


#Abuse of Funcnionalities


  def getEventsAbuse(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Abuse of Funcionalities"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#Anti-Scrapping 

  def getEventsScraping(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Anti-Scraping"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata
  
  #Application Leakage

  def getEventsAppleakage(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Application Information Leakage"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Application Misconfiguration

  def getEventsAppmiss(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Application Misconfiguration"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Authentication Time Restriction

  def getEventsAuthtime(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Authentication Time Resection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Automation

  def getEventsAutomation(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Automation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Bank Account Leakage

  def getEventsBank(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Bank Account Number Leakage"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Bruteforce

  def getEventsBrute(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Brute Force"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Buffer Overflow

  def getEventsBuffer(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Buffer Overflow"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #CCN leakage

  def getEventsCCN(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"CCN"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Code Injection

  def getEventsCode(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Code Injection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Content Spoofing

  def getEventsContent(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Content Spoofing"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Cookie Poisoning

  def getEventsCookie(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Cookie Poisoning"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Cross Site Scripting

  def getEventsCrosssIte(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Cross Site Scripting"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #CSRF

  def getEventsCSRF(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"CSRF"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Cross SIte Request Forgery

  def getEventsCSRF2(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Cross SIte Request Forgery"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Directory Indexing

  def getEventsDirectory(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Directory Indexing"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Disable Authentication

  def getEventsDisauth(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Disabled Users Authentication Failure"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Evasion

  def getEventsEvasion(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Evasion"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Expired Client Certificate

  def getEventsExpiredc(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Expired Client Certificate Request"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Expired User failure

  def getEventsExpiredu(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Expired User Authentication Failure"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      print(res.status)
      print(res)
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #File Upload Violation

  def getEventsFileup(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"File Upload Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Fingerprinting

  def getEventsFinger(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Fingerprinting"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Folder Access Violation

  def getEventsFolder(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Folder Access Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Form Field Tampering

  def getEventsForm(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Form Field Tampering"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #High Resource Utilization

  def getEventsHRU(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"High Resource Utilization"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Hot Link

  def getEventsHotlink(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Hot Link"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #HTTP Method Violation

  def getEventsMethod(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"HTTP Method Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #HTTP Request Body Side

  def getEventsBodyside(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"HTTP Request Body Size Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #HTTP Request Body Violation

  def getEventsBodyv(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"HTTP Request Body Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #HTTP Request Header Violation

  def getEventsHeaderv(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"HTTP Request Header Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #HTTP Request Smuggling

  def getEventsHTTPsm(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"HTTP Request Smuggling"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #HTTP Response Splitting

  def getEventsHTTPsp(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"HTTP Response Splitting"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #HTTP RFC Violatio

  def getEventsHTTPRFC(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"HTTP RFC Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      print(res.status)
      print(res)
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Injection

  def getEventsInjection(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Injection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Input Val

  def getEventsInputval(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Input Validation Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Insecure communications

  def getEventsInsecurec(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Insecure communications"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Insufficient Session Expiration

  def getEventsInsufs(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Insufficient Session Expiration"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Invalid Client Certificate Attributes

  def getEventsInvalidclc(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Invalid Client Certificate Attributes"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #LDAP Injection

  def getEventsLDAPI(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"LDAP Injection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Low Bandwidth Request flood

  def getEventsLowband(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Low Bandwidth Request flood"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Mail Command Injection

  def getEventsMaili(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Mail Command Injection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Non-Valid XML Structure

  def getEventsnonXML(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Non-Valid XML Structure"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Null byte Injection

  def getEventsNullbyte(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Null byte Injection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #OS Commanding

  def getEventsOScom(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"OS Commanding"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Parameter Tampering

  def getEventsParamta(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Parameter Tampering"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Path Traversal

  def getEventsPatht(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Path Traversal"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Predictable Resource Location

  def getEventsPredictable(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Predictable Resource Location"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Request flood - IP threshold

  def getEventsRequestfloodip(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Request flood - IP threshold"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Request flood - URL threshold

  def getEventsRequestfloodurl(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"URL threshold"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Response Header Violation

  def getEventsResponseh(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Response Header Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Revoked Client Certificate Request

  def getEventsRevoked(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Revoked Client Certificate Request"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #RFI

  def getEventsRFI(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"RFI"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Routing Detour

  def getEventsRoutingd(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Routing Detour"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Security Misconfiguration

  def getEventsSecmis(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Security Misconfiguration"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Security Rule

  def getEventsSecrule(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Security Rule"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Server Information Leakage

  def getEventsSecleak(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Server Information Leakage"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Server Misconfiguration

  def getEventsServermis(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Server Misconfiguration"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Session Fixation

  def getEventsSessionfix(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Session Fixation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Session Flow Violation

  def getEventsSessionflow(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Session Flow Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Session Hijacking

  def getEventsSessionhj(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Session Hijacking"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata
  
  #Session Management Attack

  def getEventsSessionma(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Session Management Attack"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #Session Prediction

  def getEventsSessionpred(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Session Prediction"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

  #SOAP Array Abuse

  def getEventsSOAParray(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"SOAP Array Abuse"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

 #SQL Injection

  def getEventsSQLi(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"SQL Injection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

 #SSI Injection

  def getEventsSSi(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"SSI Injection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

 #Status Code Unknown

  def getEventsStatusU(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Status Code Unknown"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

 #Unauthorized Access Attempt

  def getEventsUnauthacc(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Unauthorized Access Attempt"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

 #URL Access Violation

  def getEventsURLacc(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"URL Access Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

 #URL Length Violation

  def getEventsURLlength(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"URL Length Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#Web Services Abuse

  def getEventsWebabu(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Web Services Abuse"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#Web Worms

  def getEventsWebworm(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"Web Worms"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#XML Abuse

  def getEventsXMLabu(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"XML Abuse"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#XML Attribute Blowup

  def getEventsXMLblow(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"XML Attribute Blowup"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#XML Entity Expansion

  def getEventsXMLentity(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"XML Entity Expansion"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#XML External Entities

  def getEventsXMLext(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"XML External Entities"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#XML Injection

  def getEventsXMLi(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"XML Injection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#XML Schema Violation

  def getEventsXMLSch(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"XML Schema Violation"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#XPath Injection

  def getEventsXpath(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"xPath Injection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#XPath Injection

  def getEventsXQuery(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"XQuery Injection"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata

#XSS

  def getEventsXSS(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''},
                    {"type":"orFilter",
                        "filters":[{"type":"termFilter","inverseFilter":false,"field":"violationType","value":"XSS"}]}],
                    "pagination":{"page":0,"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"STRING"}]}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    return appdata
  
  def getAttackType(self,timelower,timeupper):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    payload = '''{"aggregation":{"type":"groupBy","aggName":"Host","aggField":"host","criteria":[{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,"upper":''' + timeupper + ''',"lower":''' + timelower + '''}],"aggregation":{"type":"groupBy","aggName":"violationType","aggField":"violationType","aggregation":{"type":"count","aggName":"hitCount"}}}}'''


    headers = {
      'Authorization': 'Bearer ' + self.bearerToken,
      'requestEntityids': self.tenantID,
      'Cookie': 'Authorization=' + self.bearerToken,
      'Content-Length': len(payload),
      'Content-Type': 'application/json;charset=UTF-8'
    }

    conn.request("POST", "/mgmt/monitor/reporter/reports/APPWALL_REPORTS", payload, headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata