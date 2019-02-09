import requests
import sys

#Usage:       python ./CloudIPLookup.py input.txt
#             input.txt is a text file where all of the IPs you want to check are on a separate line
#Description: This script checks the IPs in the input file and contacts the ip-api.com API in order to find their AS, ISP and ORG.
#             It then compares the received information with known keywords associated with Cloud providers, and alerts the user if there are any.
#             The script won't pick up every cloud provider so it's important to still go over the raw output just in case.
#             This was originally made for a Vulnerability Assessment test so that we weren't hitting Cloud infrastructure.

#A list of keywords typically associated with Cloud infrastructure
SUSPICIOUS_KEYWORDS=["SoftLayer","AWS","Amazon","Google","GCP","Microsoft","Azure","Rackspace","Kamatera","Cloud"]

#Where the output file is stored
OUTPUT_FILENAME='output.txt'

#The limit to the amount of IPs you can fit in a single request
API_LIMIT=100

jsonInput=[]

#Input error check
if len(sys.argv)<2:
    print("Usage: python " + sys.argv[0] + " input.txt")
    print("Make sure to include the filename containing the IPs all on their own line")
    quit()

#Formatting the list of IPs to be passed to the API
IPCounter=0
with open(sys.argv[1]) as IPInputFile:
    for line in IPInputFile:
        IPCounter+=1
        jsonInput.append({"query":line.strip()})

response=[]

#The API only allows 100 IPs to be checked in a single request so if there are more than that they have to be split into multiple requests
for IPNum in range((IPCounter//API_LIMIT)+1):
    #Send the request to the API
    req = requests.post('http://ip-api.com/batch', json=jsonInput[IPNum*API_LIMIT:(IPNum+1)*API_LIMIT])
    response.extend(req.json())

suspiciousCounter=0
output = open(OUTPUT_FILENAME,'w+')

#Go over the response for every IP and check whether it contains any triggering keywords
for IPResponse in response:
    output.write(str(IPResponse) +"\n")
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in IPResponse['isp'].lower():
            suspiciousCounter+=1
            print("WARNING: " + IPResponse['query'] + "'s ISP is " + IPResponse['isp'])
        elif keyword.lower() in IPResponse['as'].lower():
            suspiciousCounter+=1
            print("WARNING: " + IPResponse['query'] + "'s AS is " + IPResponse['AS'])
        elif keyword.lower() in IPResponse['org'].lower():
            suspiciousCounter+=1
            print("WARNING: " + IPResponse['query'] + "'s ORG is" + IPResponse['org'])
output.close()

print(str(suspiciousCounter)+"/"+str(IPCounter)+" IPs are potential SoftLayer, AWS, GCP, Azure, Rackspace or Kamatera IPs")
print("No matter the result please ensure to check the entire output at " + OUTPUT_FILENAME)


            
