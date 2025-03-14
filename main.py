import CWAPI
import csv
import time
import json
from datetime import datetime, timezone
import GetFiles

def convert_timestamp(timestamp):
    try:
        return datetime.fromtimestamp(int(timestamp) / 1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return ""  # Return empty string if conversion fails
def secevents_to_csv(x):
    
    for item in x.get("data", []):
        row_data = item.get("row", {})
        # Extract and convert receivedTimeStamp
        timestamp = row_data.get("receivedTimeStamp", "")
        human_readable_timestamp = convert_timestamp(timestamp)
        # Extract country code from enrichmentContainer if available
        country_code = ""
        enrichment_container = row_data.get("enrichmentContainer", "{}")
        try:
            enrichment_data = json.loads(enrichment_container)
            country_code = enrichment_data.get("geoLocation", {}).get("countryCode", "")
        except json.JSONDecodeError:
            pass  # If parsing fails, keep country_code as an empty string

        rows.append([
            row_data.get("transId", ""),
            row_data.get("webApp", ""),
            row_data.get("title", ""),
            row_data.get("violationType", ""),
            row_data.get("violationCategory", ""),
            row_data.get("details", ""),
            country_code,
            row_data.get("paramName", ""),
            row_data.get("parameterName", ""),
            row_data.get("paramType", ""),
            row_data.get("paramValue", ""),
            row_data.get("uri", ""),
            row_data.get("appPath", ""),
            row_data.get("directory", ""),
            row_data.get("sourceIp", ""),  # Adjusted to match "sourceIP"
            row_data.get("host", ""),
            human_readable_timestamp,
            row_data.get("targetModule", ""),
            row_data.get("module", ""),
            row_data.get("action", "")
        ])
    with open('SecurityEvents Summary.csv', "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(rows)    # Write data

    return 

rows = []
tiempo=int(time.time())


comp=input("Company name: ")
un=input("Enter your username: ")
ps=input("Enter your password: ")
dtl=input("Enter start date&time - format yyyy-mm-dd hh:mm:ss: ")
dtu=input("Enter end date&time - format yyyy-mm-dd hh:mm:ss: ")
print(dtl)
print(dtu)

utc_datetimelower=datetime.strptime(dtl, "%Y-%m-%d %H:%M:%S")
utc_datetimeupper=datetime.strptime(dtu, "%Y-%m-%d %H:%M:%S")
netl = int(utc_datetimelower.timestamp() * 1000)
netu = int(utc_datetimeupper.timestamp() * 1000)
etl=str(netl)
etu=str(netu)
#raise Exception("Debuggins stop")
print(netl)
print(netu)
#AAT (Authentication, Authorization and Tenant ID)
z=CWAPI.CloudWAFAPI(username=un,password=ps)
z.login()
#print(x)
#eventvalid=x['data']
#eventvalid=str(eventvalid)
#print(eventvalid)
headers = [
    "transId", "webApp", "title", "violationType", "violationCategory",
    "details", "Country Code", "paramName", "parameterName", "paramType", 
    "paramValue", "uri", "appPath", "directory", "sourceIP", "host", 
    "receivedTimeStamp", "targetModule", "module", "action"
]
# Write Headers to CSV
with open('SecurityEvents Summary.csv', "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(headers)  # Write headers
Delay=5
x=z.getEventsAbuse(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Abuse of Functionality events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsScraping(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Anti-Scrapping events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsAppleakage(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"App Leakage events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsAppmiss(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Application Misconfiguration events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsAuthtime(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Authentication Time Restriction events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsAutomation(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Automation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsBank(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Bank information leakage (if configured) saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsBrute(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Bruteforce events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsBuffer(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Buffer Overflow events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsCCN(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Credit Card Number leakage (if configured) events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsCode(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Code injection events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsContent(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Content spoofing events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsCookie(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Cookie Poisoning events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsCrosssIte(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Cross-site-scripting events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsCSRF(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"CSRF events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsCSRF2(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"CSRF2 events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsDirectory(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Directory Indexing events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsDisauth(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Disable Authentication events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsExpiredc(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Expired client certificate events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsEvasion(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Evasion events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsExpiredu(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Expired user events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsFileup(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"File upload violation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsFolder(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Folder access violation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsFinger(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Fingerprinting events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsForm(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Form Field Tampering events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsHRU(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"High Resource Utilization events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsHotlink(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Hot Link events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsMethod(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"HTTP Method Violation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsBodyside(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"HTTP Request body side events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsBodyv(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"HTTP Request body vilation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsHeaderv(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"HTTP Request Header Violation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsHTTPsm(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"HTTP Request Smuggling events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsHTTPsp(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"HTTP Response Splitting events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsHTTPRFC(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"HTTP RFC Violation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsInjection(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Injection events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsInputval(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Input Validation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsInsecurec(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Insecure Communication events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsInsufs(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Insufficient Session Expiration events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsInvalidclc(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Invalid Client Certificate Attributes events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsLDAPI(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"LDAP Injection events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsLowband(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Low Bandwidth Request flood events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsMaili(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Mail Command Injection events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsnonXML(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Non-Valid XML Structure events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsNullbyte(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Null byte Injection events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsOScom(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"OS Commanding events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsParamta(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Parameter Tampering events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsPatht(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Path Traversal events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsPredictable(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Predictable Resource Location events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsRequestfloodip(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Request flood - IP threshold events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsRequestfloodurl(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Request flood - URL threshold events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsResponseh(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Response Header Violation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsRevoked(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Revoked Client Certificate Request events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsRFI(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Remote File Inclusion events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsRoutingd(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Routing Detour events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsSecmis(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Security Misconfiguration events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
#x=z.getEventsSecrule(timelower=etl,timeupper=etu)
#secevents_to_csv(x)
#print(f"Security Rule events saved at: {'SecurityEvents Summary.csv'}")
x=z.getEventsSecleak(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Server Information Leakage events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsServermis(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Server Misconfiguration events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsSessionfix(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Session Fixation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsSessionflow(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Session Flow Violation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsSessionhj(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Session Hijacking events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsSessionma(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Session Management Attack events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsSessionpred(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Session Prediction events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsSOAParray(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"SOAP Array Abuse events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsSQLi(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"SQL Injection events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsSSi(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"SSI Injection events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsStatusU(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Status Code Unknown events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsUnauthacc(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Unauthorized Access Attempt events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsURLacc(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"URL Access Violation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsURLlength(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"URL Length Violation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsWebabu(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Web Services Abuse events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsWebworm(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"Web Worms events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsXMLabu(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"XML Abuse events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsXMLblow(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"XML Attribute Blowup events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsXMLentity(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"XML Entity Expansion events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsXMLext(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"XML External Entities events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsXMLi(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"XML Injection events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsXMLSch(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"XML Schema Violation events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsXpath(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"XPath Injection events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsXQuery(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"XQuery Injection events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)
x=z.getEventsXSS(timelower=etl,timeupper=etu)
secevents_to_csv(x)
print(f"XSS events saved at: {'SecurityEvents Summary.csv'}")
time.sleep(Delay)


GetFiles.docs(dtl,dtu,comp)

