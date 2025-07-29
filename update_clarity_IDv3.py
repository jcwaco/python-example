import json
import requests
import sys
import logging
import datetime
from datetime import date
import argparse
import csv

def update_clarity_ID (project,rally_apikey, perform_update: bool):
    global delimiter
    global log_header
    global logger
    # 
    the_initiatives = dict()
    #
    # if not(initiatives_file == False):
        
    #     #print("Reading input from file: " + initiatives_file)
    #     logger.info(log_header + "Reading input from file: " + str(initiatives_file))
    #     with open(initiatives_file, "r", newline='', encoding='utf-8-sig') as csvfile:
    #         rows = csv.DictReader(csvfile, fieldnames=("Initiative","ClarityID"),delimiter=',')
    #         #
    #         for row in rows:
    #            # print(row['Initiative'], row['ClarityID'])
    #            my_Initiative = row['Initiative']
    #            my_ClarityID = row['ClarityID']
    #            the_initiatives.update({my_Initiative: my_ClarityID})
            
    #         csvfile.close()
            
    # else:
    #     logger.info(log_header + "**No csv file. Initiative and ClarityID values will be read from Initiatives.**")
 
    # # Rally endpoints & query parameters
    rally_base_url = "https://rally1.rallydev.com/slm/webservice/v2.0/"
    rally_initiative = rally_base_url + "portfolioitem/initiative"
    rally_capability = rally_base_url + "portfolioitem/capability"
    rally_feature = rally_base_url + "portfolioitem/feature"
    rally_story = rally_base_url + "hierarchicalrequirement"
    rally_defect = rally_base_url + "defect"
    rally_project_base = "https://rally1.rallydev.com/slm/webservice/v2.0/project/"
    rally_project_query = '?query=(Name = "' + project + '")'
    rally_project_fields = "&fetch=Name,ObjectID"
    rally_query_params = "&fetch=Name,FormattedID,ObjectID,c_Initiative,c_ClarityID&projectScopeDown=true&pagesize=2000"

    headers = {
        'ZSESSIONID': rally_apikey,
        'Content-Type': 'application/json'
    }
    # Get Rally Project's ObjectID
    rally_project_response = requests.request(
        "GET", "https://rally1.rallydev.com/slm/webservice/v2.0/project" + rally_project_query + rally_project_fields, headers=headers, verify=verify_cert_path)
    if rally_project_response:
        logger.info(log_header + 'Success: ' + str(rally_project_response.status_code) + ' Rally Project returned successfully.')
        # print (rally_feature_response.request.headers)
    else:
        logger.error(log_header + 'Error: ' + str(rally_project_response.status_code) + rally_project_response.text + ' Rally Project was not Returned.')
        sys.exit('Failed REST call')

    the_rally_project = json.loads(rally_project_response.text)
    
    rally_projectOID = str(the_rally_project['QueryResult']['Results'][0]['ObjectID'])

    rally_query = "?project=" + rally_project_base + rally_projectOID
    #
    # # Fetch the Rally Initiatives
    rally_initiative_response = requests.request(
        "GET", rally_initiative + rally_query + rally_query_params, headers=headers, verify=verify_cert_path)
    if rally_initiative_response:
        logger.info(log_header + 'Success: ' + str(rally_initiative_response.status_code) + ' Rally Initiatives returned successfully.')
    else:
        logger.error(log_header + 'Error: ' + str(rally_initiative_response.status_code) + rally_initiative_response.text + ' Rally Initiatives were not Returned.')
        sys.exit('Failed REST call')     
    # 
    the_rally_initiatives = json.loads(rally_initiative_response.text)
    logger.info(log_header + ' ' + str(len(the_rally_initiatives['QueryResult']['Results'])) + ' Rally Initiatives fetched')
    #
    # Load Dict - 'the_initiatives' with the key/value pairs read from Fetched Initiatives
    for i in range (len(the_rally_initiatives['QueryResult']['Results'])):
        An_Initiative = str(the_rally_initiatives['QueryResult']['Results'][i]['c_Initiative'])
        The_ClarityID = str(the_rally_initiatives['QueryResult']['Results'][i]['c_ClarityID'])
        # Skip the Initiative if it does not have a value in 'c_Initiative'. Otherwise add its values for 'c_Initiative' and 'c_ClarityID' to the_initiatives Dict
        if (An_Initiative != 'None'):
            the_initiatives.update ({An_Initiative: The_ClarityID})
    #
    #
    # # Fetch the Rally Capabilities
    rally_capability_response = requests.request(
        "GET", rally_capability + rally_query + rally_query_params, headers=headers, verify=verify_cert_path)
    if rally_capability_response:
        logger.info(log_header + 'Success: ' + str(rally_capability_response.status_code) + ' Rally Capabilities returned successfully.')
    else:
        logger.error(log_header + 'Error: ' + str(rally_capability_response.status_code) + rally_capability_response.text + ' Rally Capabilities were not Returned.')
        sys.exit('Failed REST call')     
    # 
    the_rally_capabilities = json.loads(rally_capability_response.text)
    logger.info(log_header + ' ' + str(len(the_rally_capabilities['QueryResult']['Results'])) + ' Rally capabilities fetched')
    # #
    for i in range (len(the_rally_capabilities['QueryResult']['Results'])):
        Capability_Initiative = str(the_rally_capabilities['QueryResult']['Results'][i]['c_Initiative'])
        Capability_ClarityID = str(the_rally_capabilities['QueryResult']['Results'][i]['c_ClarityID'])
        if (Capability_Initiative != 'None'):   
            #
            if perform_update:
                if (Capability_ClarityID != the_initiatives[Capability_Initiative]):
                    update_capability_response = requests.request("POST",rally_capability + '/' + str(the_rally_capabilities['QueryResult']['Results'][i]['ObjectID']), json={"PortfolioItem/capability": {"c_ClarityID": the_initiatives[Capability_Initiative]}}, headers=headers, verify=verify_cert_path)
                    # logger.info(log_header + "POST " + rally_feature + '/' + str(the_rally_features['QueryResult']['Results'][i]['ObjectID']) + "  ")
                    # 
                    if update_capability_response:
                        logger.info(log_header + 'Success! Rally Capability: ' + str(the_rally_capabilities['QueryResult']['Results'][i]['FormattedID']) + ' was updated successfully.')
                    else:
                        logger.error(log_header + 'Error! Rally Capability: ' + str(the_rally_capabilities['QueryResult']['Results'][i]['FormattedID']) + ' was not Updated.')
                        sys.exit('Failed REST call')
                else:
                    logger.info(log_header + "Item Skipped: " + "Rally Capability - " + str(the_rally_capabilities['QueryResult']['Results'][i]['FormattedID']) + " Did not need to be updated.")
            
            else:
                logger.info(log_header + "SIMULATION: " + "Rally Capability - " + str(the_rally_capabilities['QueryResult']['Results'][i]['FormattedID']) + " Not Updated.")
                
        else:
            logger.info(log_header + "Rally Capability - " + the_rally_capabilities['QueryResult']['Results'][i]['FormattedID'] + " not updated. It has no Initiative Selected.")

        # # Fetch the Rally Features
        rally_feature_response = requests.request(
            "GET", rally_capability + '/' + str(the_rally_capabilities['QueryResult']['Results'][i]['ObjectID']) + '/Children' + rally_query + rally_query_params, headers=headers, verify=verify_cert_path)
        if rally_feature_response:
            logger.info(log_header + 'Success: ' + str(rally_feature_response.status_code) + ' Rally Features returned successfully.')
        else:
            logger.error(log_header + 'Error: ' + str(rally_feature_response.status_code) + rally_feature_response.text + ' Rally Features were not Returned.')
            sys.exit('Failed REST call')     
        # 
        the_rally_features = json.loads(rally_feature_response.text)
        logger.info(log_header + ' ' + str(len(the_rally_features['QueryResult']['Results'])) + ' Rally Features fetched')
        # #
        for k in range (len(the_rally_features['QueryResult']['Results'])):
            Feature_Initiative = str(the_rally_features['QueryResult']['Results'][k]['c_Initiative'])
            Feature_ClarityID = str(the_rally_features['QueryResult']['Results'][k]['c_ClarityID'])
            if (Feature_Initiative != 'None'):   
                #
                if perform_update:
                    if (Feature_ClarityID != the_initiatives[Feature_Initiative]):
                        update_feature_response = requests.request("POST",rally_feature + '/' + str(the_rally_features['QueryResult']['Results'][k]['ObjectID']), json={"PortfolioItem/Feature": {"c_ClarityID": the_initiatives[Feature_Initiative]}}, headers=headers, verify=verify_cert_path)
                    # logger.info(log_header + "POST " + rally_feature + '/' + str(the_rally_features['QueryResult']['Results'][i]['ObjectID']) + "  ")
                    # 
                        if update_feature_response:
                            logger.info(log_header + 'Success! Rally Feature: ' + str(the_rally_features['QueryResult']['Results'][k]['FormattedID']) + ' was updated successfully.')
                        else:
                            logger.error(log_header + 'Error! Rally Feature: ' + str(the_rally_features['QueryResult']['Results'][k]['FormattedID']) + ' was not Updated.')
                            sys.exit('Failed REST call')
                    else:
                        logger.info(log_header + "Item Skipped: " + "Rally Feature - " + str(the_rally_features['QueryResult']['Results'][k]['FormattedID']) + " Did not need to be updated.")
                else:
                    logger.info(log_header + "SIMULATION: " + "Rally Feature - " + str(the_rally_features['QueryResult']['Results'][k]['FormattedID']) + " Not Updated.")
                    
            else:
                logger.info(log_header + "Rally Feature - " + the_rally_features['QueryResult']['Results'][k]['FormattedID'] + " not updated. It has no Initiative Selected.")
            # Moved the Story Processing, so that it happens whether or not the item's parent Feature was processed.
            #
            # Fetch all child User Stories for the Feature
            userstory_response=requests.request("GET", rally_feature + '/' + str(the_rally_features['QueryResult']['Results'][k]['ObjectID']) + '/UserStories' + rally_query + rally_query_params, headers=headers, verify=verify_cert_path)
            
            the_user_stories = json.loads(userstory_response.text)
            for j in range (len(the_user_stories['QueryResult']['Results'])):
                Story_Initiative = str(the_user_stories['QueryResult']['Results'][j]['c_Initiative'])
                Story_ClarityID = str(the_user_stories['QueryResult']['Results'][j]['c_ClarityID'])
                if (Story_Initiative != 'None'):
                    if perform_update:
                        if (Story_ClarityID != the_initiatives[Story_Initiative]):
                            update_stories_response = requests.request("POST",rally_story + '/' + str(the_user_stories['QueryResult']['Results'][j]['ObjectID']), json={"HierarchicalRequirement": {"c_ClarityID": the_initiatives[Story_Initiative]}}, headers=headers, verify=verify_cert_path)
                            # logger.info(log_header + "POST " + rally_story + '/' + str(the_user_stories['QueryResult']['Results'][j]['ObjectID']) + "  ")
                            if update_stories_response:
                                logger.info(log_header + 'Success! User Story: ' + str(the_user_stories['QueryResult']['Results'][j]['FormattedID']) + ' updated successfully.')
                            else:
                                logger.error(log_header + 'Error! User Story: ' + str(the_user_stories['QueryResult']['Results'][j]['FormattedID']) + ' was not Updated.')
                                sys.exit('Failed REST call')
                        else:
                            logger.info(log_header + "Item Skipped: " + "Rally User Story - " + str(the_user_stories['QueryResult']['Results'][j]['FormattedID']) + " Did not need to be updated.")
                    else:
                        logger.info(log_header + "SIMULATION: " + "Rally User Story - " + str(the_user_stories['QueryResult']['Results'][j]['FormattedID']) + " Not Updated.")
                else:
                    logger.info(log_header + "Rally User Story - " + the_user_stories['QueryResult']['Results'][j]['FormattedID'] + " not updated. It has no Initiative Selected.")
    #
    # # Fetch the Rally Defects
    rally_defect_response = requests.request(
        "GET", rally_defect + rally_query + rally_query_params, headers=headers, verify=verify_cert_path)
    if rally_defect_response:
        logger.info(log_header + 'Success: ' + str(rally_defect_response.status_code) + ' Rally defects returned successfully.')
    else:
        logger.error(log_header + 'Error: ' + str(rally_defect_response.status_code) + rally_defect_response.text + ' Rally defects were not Returned.')
        sys.exit('Failed REST call')     
    # 
    the_rally_defects = json.loads(rally_defect_response.text)
    logger.info(log_header + ' ' + str(len(the_rally_defects['QueryResult']['Results'])) + ' Rally defects fetched')
    #
    # #
    for i in range (len(the_rally_defects['QueryResult']['Results'])):
        Defect_Initiative = str(the_rally_defects['QueryResult']['Results'][i]['c_Initiative'])
        Defect_ClarityID = str(the_rally_defects['QueryResult']['Results'][i]['c_ClarityID'])
        if (Defect_Initiative != 'None'):
            #  
            if perform_update:
                if (Defect_ClarityID != the_initiatives[Defect_Initiative]):
                    update_defect_response = requests.request("POST",rally_defect + '/' + str(the_rally_defects['QueryResult']['Results'][i]['ObjectID']), json={"Defect": {"c_ClarityID": the_initiatives[Defect_Initiative] }}, headers=headers, verify=verify_cert_path)
                    # logger.info(log_header + "POST " + rally_defect + '/' + str(the_rally_defects['QueryResult']['Results'][i]['ObjectID']) + "  ")
                    if update_defect_response:
                        logger.info(log_header + 'Success! Rally defect: ' + str(the_rally_defects['QueryResult']['Results'][i]['FormattedID']) + ' was updated successfully.')
                    else:
                        logger.error(log_header + 'Error! Rally defect: ' + str(the_rally_defects['QueryResult']['Results'][i]['FormattedID']) + ' was not Updated.')
                        sys.exit('Failed REST call')
                else:
                        logger.info(log_header + "Item Skipped: " + "Rally Defect - " + str(the_rally_defects['QueryResult']['Results'][i]['FormattedID']) + " Did not need to be updated.")
            else:
                logger.info(log_header + "SIMULATION: " + "Rally defect - " + str(the_rally_defects['QueryResult']['Results'][i]['FormattedID']) + " Not Updated.")
                
        else:
            logger.info(log_header + "Rally defect - " + the_rally_defects['QueryResult']['Results'][i]['FormattedID'] + " not updated. It has no Initiative Selected.")

    logger.info(log_header + "Update Complete")
    
def Init():
    global scriptName
    global delimiter
    global log_header
    global logLevel
    global logger
    global options

    scriptName = "Update Clarity ID"
    delimiter = " :: "
    log_header = scriptName + delimiter

    functionName = "Init"
    my_log_header = log_header + functionName + delimiter

    logLevel = "INFO"

    now = datetime.datetime.now()
    today = date.today()
    curDate = today.strftime("%m-%d-%y")
    logFileName = (("%s_%s") % (curDate,scriptName))
    logger = logging.getLogger(logFileName)
    hdlr = logging.FileHandler(logFileName + '.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)

    p = argparse.ArgumentParser(description="Update Clarity ID - Lookup selected Initiative for a work item and set the corresponding ClarityID field value", formatter_class=argparse.RawDescriptionHelpFormatter,epilog="Example Usage:   python3 update_clarityID.py --filename SampleInput.csv")
    # p.add_argument('-o', '--project_OID', default="773576607353", help="The Top Project's Object ID. (*This is temporary while testing).")
    p.add_argument('-p', '--project', default="Online Store", help="The name of the Top Project. Program will look for Features and Defects in this project and any child projects. Child User Stories for any Features found are also processed.")
    p.add_argument('-k', '--rally_apikey', default="_zmP8vS2iTDyPGsCdNlZJT7EBPddCkNZkzcAOJos", help="APIKey for Rally User.  Must have appropriate permissions to update work items within the Project Scope.")
    p.add_argument('-c', '--cert_path', default=False, help='Relative path to a CA cert bundle or directory for verification of SSL certificate for HTTPS requests. Requests verifies SSL certificates for HTTPS requests, just like a web browser. By default, SSL verification is disabled. If not disabled, Requests will throw a SSLError if it’s unable to verify the certificate.')
    p.add_argument('-l', '--log_level', default="DEBUG", help='Logging Level. Valid options are: DEBUG, INFO, WARNING, ERROR. Default Value: INFO')
    p.add_argument('-f', '--filename', nargs='?', default=False, help="Filename or path to csv file that contains Initiative Names and the corresponding ClarityID's.")
    p.add_argument('-u', '--perform_update', action='store_true', help='Determines whether operations are actually executed or not. Default with no command line argument is False. If -u is provided, will evaluate True.')
      
    options = p.parse_args()
    
    logLevel = options.log_level

    if (logLevel == "DEBUG"):
        logger.setLevel(logging.DEBUG)
    if (logLevel == "INFO"):
        logger.setLevel(logging.INFO)
    if (logLevel == "WARNING"):
        logger.setLevel(logging.WARNING)
    if (logLevel == "ERROR"):
        logger.setLevel(logging.ERROR)

    logger.info(my_log_header + "Start.")
    logger.info(my_log_header + now.strftime("%Y-%m-%d %H:%M:%S"))

   
    logger.debug(my_log_header + 'perform_update: ' + str(options.perform_update))
    logger.debug(my_log_header + 'logLevel: ' + logLevel)
    # logger.debug(my_log_header + 'project_OID: ' + options.project_OID)
    logger.debug(my_log_header + 'project: ' + options.project)
    logger.debug(my_log_header + 'Rally APIKey: ' + options.rally_apikey)
    logger.debug(my_log_header + 'Cert Path: ' + str(options.cert_path))
    logger.debug(my_log_header + 'File Name: ' + str(options.filename))

def main():
    global scriptName
    global delimiter
    global log_header
    global logLevel
    global logger
    global options
    global verify_cert_path

    Init()
    verify_cert_path=False
    requests.packages.urllib3.disable_warnings()

    if options.cert_path != False:
        verify_cert_path = options.cert_path
        logger.info(log_header + 'verify_cert_path = %s' % str(verify_cert_path))
    else: 
        logger.info(log_header + '*** Running without SSL Certificate Verification ***')
        

    update_clarity_ID(options.project, options.rally_apikey, options.perform_update)
    
if (__name__ == "__main__"):
    main()