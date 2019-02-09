Usage:       python ./CloudIPLookup.py input.txt
             input.txt is a text file where all of the IPs you want to check are on a separate line
Description: This script checks the IPs in the input file and contacts the ip-api.com API in order to find their AS, ISP and ORG.
             It then compares the received information with known keywords associated with Cloud providers, and alerts the user if there are any.
             The script won't pick up every cloud provider so it's important to still go over the raw output just in case.
             This was originally made for a Vulnerability Assessment test so that we weren't hitting Cloud infrastructure.