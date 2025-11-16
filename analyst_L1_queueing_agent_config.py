"""
Created on Thu Sep 29 11:05 2024

AUTHOR      : Sai Koushik Parachi
EMAIL       : Parachi.SaiKoushik@yokogawa.com
VERSION     : v1
FileName    : analyst_L1_queueing_agent_config.py
Objective   : This python file holds all the configuration and elastic search queries for the triggered Jenkin Job.

Parameters  :
    INPUT   : None.
    OUPUT   : kibana_alert_queries - Dictionary.

"""
from analyst_L1_queueing_agent_imports import logger, pdb


irpc_regions = {"irpc_region": ['IRPC'], }

kibana_jira_field_mappings = {"irpc_fields_mapping": {
    "Summary": "issue['fields']['summary']", "Project_Name": "issue['fields']['project']['name']", "Issue_ID": "issue['id']",
    "Project_Key": "issue['fields']['project']['key']", "Issue_Status": "issue['fields']['status']['name']",
    "Issue_Key": "issue['key']", "Issue_Type": "issue['fields']['issuetype']['name']", "Issue_Priority": "issue['fields']['priority']['name']",
    "Assignee_Name": "issue['fields']['assignee']['displayName']", "Assignee_ID": "issue['fields']['assignee']['accountId']",
    "Reporter_Name": "issue['fields']['reporter']['displayName']", "Reporter_ID": "issue['fields']['reporter']['accountId']",
    "Creator_Name": "issue['fields']['creator']['displayName']", "Creator_ID": "issue['fields']['creator']['accountId']",
    "Issue_Created": "issue['fields']['created']", "Issue_Updated": "issue['fields']['updated']", "Issue_Due_Date": "issue['fields']['duedate']",
    "Issue_Priority": "issue['fields']['priority']['name']", "Issue_Resolution": "issue['fields']['resolution']['name']",
    "Issue_Last_Viewed": "issue['fields']['lastViewed']", "Issue_Project_Type_Key": "issue['fields']['project']['projectTypeKey']",
    "Issue_Project_URL": "issue['fields']['project']['self']", "Issue_Project_Description": "issue['fields']['project']['projectCategory']['description']",
    "Issue_Resolution_Date": "issue['fields']['resolutiondate']", "Issue_Due_Date": "issue['fields']['duedate']", "Issue_Votes": "issue['fields']['votes']['votes']",
    "Custom_field_Alert_Type": "issue['fields']['customfield_10099']", "Custom_Field_Plant_ID":	"issue['fields']['customfield_10102']",
    "Custom_Field_Primary_SLA":	"issue['fields']['customfield_10107']", "Custom_Field_Source":	"issue['fields']['customfield_10057']",
    "Custom_Field_Time_For_Advise": "issue['fields']['customfield_10106']", "Custom_Field_Time_To_First_Response":	"issue['fields']['customfield_10041']",
    "Description": "issue['fields']['description']['content'][0]['content'][0]['text']",
    "Custom_Field_Severity": "issue['fields']['description']['content'][0]['content'][8]['text']", },

    "ptt_all_plants_fields_mapping": {
    "Summary": "issue['fields']['summary']", "Project_Name": "issue['fields']['project']['name']", "Issue_ID": "issue['id']",
    "Project_Key": "issue['fields']['project']['key']", "Issue_Status": "issue['fields']['status']['name']",
    "Issue_Key": "issue['key']", "Issue_Type": "issue['fields']['issuetype']['name']", "Issue_Priority": "issue['fields']['priority']['name']",
    "Custom_Field_Plant_ID": "issue['fields']['customfield_10216']['value']",
    "Issue_Created": "issue['fields']['created']", "Issue_Updated": "issue['fields']['updated']", 
    
     }
}



Jira_Account_ID = {'Jira_Admin': {'Admin_API_ID': 'API_Key'},
                   
                   }