"""
Created on Thu Sep 29 11:05 2025

AUTHOR      : Sai Koushik Parachi
EMAIL       : Parachi.SaiKoushik@yokogawa.com
VERSION     : v1
FileName    : analyst_L1_processing_agent_main.py
Objective   : This python file helps to perform below tasks in and update the same in JIRA and Elastic DB.
    1. Connect to Elastic DB and fetch the latest tickets saved in it.
    2. Filter the tickets to other than "Resolved/closed" status.
    3. Assign the tickets to Automation account by updating "Assigned To Me" to "ITOTSOC Automation User".
    4. Modify the status of JIRA ticket from "Open" to "Work In Progress" or "Work In Progress" to "Waiting For Customer" etc.
    5. Update the JIRA ticket's Organization to "PTT".
    6. Using AI - Compare alert details with predefined usecase knowledge.
    7. Using AI - Generate recommandations to tickets and update the same in "Reply to Customer pane" of JIRA tickets. 
    8. Ticket Resolution: Read the latest customer comments and interpret as "Know Activity" or "Unknown Activity" and take the Ticket Resolution step as below.
        8.1. If "Know Activity" - Update the JIRA ticket status to "Resolved" and add the AI generated recommandations in "Reply to Customer pane".
        8.2. If "Unknown Activity" - Escalate this ticket to L2 by updating "Assign To Me" to "L2 DL".
    This Agent will perform above tasks on every 2 minutes interval for unprocessed tickets.

Parameters  :
    INPUT   : Jira and Elastic account details, 
    OUTPUT  : Latest Jira ticket details stored in Elastic DB.

Referance Doc: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-comments/#api-rest-api-3-issue-issueidorkey-comment-post
"""

from analyst_L1_processing_agent_imports import *
from analyst_L1_processing_agent_config import *
from analyst_L1_processing_agent_openai import create_openai_prompt, generate_openai_completion
agent_service_inputs = {}


def kibana_connect_es(prokect_key):
    """
    This function connects to elastic search and create ES connection object.
    Parameters
    ----------
    None.
    Returns
    -------
    es_ids: Generator Object
        DESCRIPTION: Holds the Elastic Search(ES) connection object.
    """
    try:
        es_endpoint = ysoc_secrets["ysoc_pcap_analysis_script"]["elastic_endpoint"]

        if prokect_key == 'SOC':
            es_user_name = list(
                ysoc_secrets['ysoc_pcap_analysis_script']['elastic_creds'].keys())[0]
            es_user_pswd = ysoc_secrets['ysoc_pcap_analysis_script']['elastic_creds'][es_user_name]
            if es_user_name == 'irpc_script_execution':
                basic_auth = (
                    es_user_name, es_user_pswd)
                es_ids = Elasticsearch(
                    [es_endpoint], basic_auth=basic_auth, verify_certs=False,
                    # max_retries=10, retry_on_timeout=True)
                    request_timeout=3000, retry_on_timeout=True)
                logger.info("The Exported JIRA data will be saved in Elastic")
                return es_ids
            else:
                logger.info("Unknown User details provided: ", es_user_name)
        elif prokect_key == 'SOC24027D':
            es_user_name = list(
                ysoc_secrets['ysoc_pcap_analysis_script']['elastic_creds'].keys())[1]
            es_user_pswd = ysoc_secrets['ysoc_pcap_analysis_script']['elastic_creds'][es_user_name]
            if es_user_name == 'ptt_script_execution':
                basic_auth = (
                    es_user_name, es_user_pswd)
                es_ids = Elasticsearch(
                    [es_endpoint], basic_auth=basic_auth,  verify_certs=False,
                    request_timeout=3000, retry_on_timeout=True)
                return es_ids
            else:
                logger.info("Unknown User details provided: ", es_user_name)

    except Exception as e:
        logger.error("Got error kibana_connect_es function with error:%s.", e)
        return None


def get_jira_tickets_from_elastic(project_key):
    """Fetch JIRA tickets from ElasticSearch.
    """
    try:
        es_client = kibana_connect_es(project_key)
        if not es_client:
            logger.error("Failed to connect to ElasticSearch.")
            return []

        # Define the index and query
        index_name = "elastic_index_name"
        query = {
            "query": {
                "match_all": {}
            }
        }

        # Initialize scroll
        scroll_time = "2m"
        page_size = 1000  # Number of docs per batch

        # First search
        response = es_client.search(
            index=index_name,
            body=query,
            scroll=scroll_time,
            size=page_size,

        )

        scroll_id = response['_scroll_id']
        all_hits = response['hits']['hits']

        # Scroll loop
        while True:
            response = es_client.scroll(
                scroll_id=scroll_id, scroll=scroll_time)
            hits = response['hits']['hits']
            if not hits:
                break
            all_hits.extend(hits)
        return all_hits
    except Exception as e:
        logger.error(
            "Got error in get_jira_tickets_from_elastic function with error:%s.", e)
        return []


def jira_connection_object(request_type, project_key):
    """
    This Function tries to create JIRA connect object which helps interfacing through JIRA REST API.
    Parameters
    ----------
    request_type : string objectg helps to filter JIRA REST API details.
    Returns
    -------
    jira_connection_details : Dictionary Object contains filtered JIRA REST API configuration details.

    """
    try:
        jira_connection_details = {}
        jira_connection_details |= {
            "username": list(Jira_Account_ID["PTT_Dev"].keys())[0],
            "api_token": list(Jira_Account_ID["PTT_Dev"].values())[0]}

        jira_connection_details |= {"headers": {
            "Accept": "application/json",
            "Content-Type": "application/json"}}
        jira_connection_details |= {
            "query": {'jql':  f'project = {str(project_key)}'}}
        if request_type == 'get_jira_tickets':
            jira_connection_details |= {
                "jira_url": "https://jira_url/rest/api/3/search/jql/"}
        elif request_type == 'get_bulk_jira_tickets':
            jira_connection_details |= {
                "jira_url": "https://jira_url/rest/api/3/issue/bulkfetch/"}
        elif request_type == 'create_jira_tickets':
            jira_connection_details |= {
                "jira_url": "https://jira_url/rest/api/3/issue/"}
        elif request_type == 'update_custom_field':
            jira_connection_details |= {
                "jira_url": "https://jira_url/rest/api/3/app/field/"}

        return jira_connection_details
    except Exception as e:
        logger.error("Got error in jira_request_object function with error:%s.",
                     e)


def post_latest_comments(issue, project_key, ai_agent_l1_text, jsdPublic):
    """
    This Function tries to post latest comments to JIRA tickets.
    Parameters
    ----------
    issue : Dictionary Object.
        DESCRIPTION: Holds the JIRA ticket information.
    project_key : String Object.
        DESCRIPTION: Holds the JIRA project key.
    ai_agent_l1_text_dict : Dictionary Object.
        DESCRIPTION: Holds the ai_agent_l1 text information.

    Returns
    -------
    None.
    """
    try:
        Ticket_Initial_Recommendation = "UnRecommended"
        jira_connection_details = jira_connection_object(
            'create_jira_tickets', project_key)
        # jsdPublic = False

        # If jsdPublic is True, the comment will be visible to customers in the portal.
        if jsdPublic == True:
            # ADF-compliant body
            payload = {
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": ai_agent_l1_text
                                }
                            ]
                        }
                    ]
                },
                # "jsdPublic": jsdPublic
            }
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            auth = HTTPBasicAuth(
                jira_connection_details['username'], jira_connection_details['api_token'])
            url = jira_connection_details['jira_url'] + \
                issue['key'] + '/comment'

            response = requests.post(
                url=url,
                data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                headers=headers,
                auth=auth, verify=False,
            )
        # If jsdPublic is False, the comment will not be visible to customers in the portal.
        # This is useful for internal comments that should not be visible to customers.
        elif jsdPublic == False:

            payload = {
                "body": ai_agent_l1_text,
                "public": False  # Set to True for public comment
            }

            auth = HTTPBasicAuth(
                jira_connection_details['username'], jira_connection_details['api_token'])

            # === Encode credentials ===
            auth_string = f"{jira_connection_details['username']}:{jira_connection_details['api_token']}"
            auth_bytes = auth_string.encode("ascii")
            auth_base64 = base64.b64encode(auth_bytes).decode("ascii")

            # === Headers ===
            headers = {
                "Authorization": f"Basic {auth_base64}",
                "Content-Type": "application/json"
            }

            url = "https://jira_url/rest/servicedeskapi/request/" + \
                issue['key'] + '/comment'

            # === Make the Request ===
            response = requests.post(
                url, json=payload, headers=headers, verify=False,)

        if response.status_code == 201:
            logger.info("Comment added successfully to %s", issue['key'])
            # print(f"Comment added successfully
            print(f"\nComment added successfully to {issue['key']}")
            Ticket_Initial_Recommendation = "Recommended"

        else:
            logger.error("Failed to add comment: %s - %s",
                         response.status_code, response.text)
            print(
                f"Failed to add comment: {response.status_code} - {response.text}")
        return Ticket_Initial_Recommendation
    except Exception as e:
        logger.error("Got error in post_latest_comments function with error:%s.",
                     e)
        return None


def get_issue_latest_comments(recent_comments, issue, project_key):
    """
    This Function tries to get latest comments from JIRA tickets.
    Parameters
    ----------
    issue : Dictionary Object.
        DESCRIPTION: Holds the JIRA ticket information.

    Returns
    -------
    latest_comment : String Object.
        DESCRIPTION: Holds the latest comment from JIRA ticket.
    """
    try:
        # latest_comments = None
        jira_connection_details = jira_connection_object(
            'create_jira_tickets', project_key)

        # Make the request
        response = requests.get(
            jira_connection_details['jira_url'] +
            issue['key'] + '/comment',
            auth=HTTPBasicAuth(
                jira_connection_details['username'], jira_connection_details['api_token']),
            headers={"Accept": "application/json"}, verify=False
        )

        if response.status_code == 200:
            try:
                comments = response.json().get("comments", [])
                description = issue['fields']['description']

                if comments:
                    lookback_minutes_ago = at_timestamp - \
                        timedelta(minutes=lookback_minutes)
                    for comment in comments:
                        recent_comment = {}
                        recent_comment |= {
                            "Acknowledged_by": "AI processing Agent L1"}
                        updated_time = str(comment["updated"]).replace(
                            "T", " ").split(".")[0]
                        comment_updated_time = datetime.datetime.strptime(
                            updated_time, "%Y-%m-%d %H:%M:%S")
                        print("comment_updated_time:", comment_updated_time,
                              "\n", "lookback_minutes_ago:", lookback_minutes_ago)
                        if comment_updated_time >= lookback_minutes_ago:
                            recent_comment |= {
                                "updated_timestamp": comment_updated_time}
                            recent_comment |= {
                                "comment": comment['body']['content']}
                            recent_comment |= {
                                "jsdPublic": comment["jsdPublic"]}
                            recent_comment |= {
                                "proceed_for_acknowledgement": True}

                            # recent_comment.append(comment)
                        else:
                            recent_comment |= {
                                "proceed_for_acknowledgement": False}
                        recent_comment |= {
                            "Acknowledged": "Comment"}
                        recent_comments.append(recent_comment)
                elif description:
                    recent_comment = {}
                    recent_comment |= {
                        "Acknowledged_by": "AI Agent L1"}
                    updated_time = str(issue['fields']['updated']).replace(
                        "T", " ").split(".")[0]
                    comment_updated_time = datetime.datetime.strptime(
                        updated_time, "%Y-%m-%d %H:%M:%S")
                    recent_comment |= {
                        "updated_timestamp": comment_updated_time}
                    recent_comment |= {
                        "comment": issue['fields']['description']}
                    recent_comment |= {
                        "jsdPublic": True}
                    # recent_comment.append(comment)
                    recent_comment |= {
                        "proceed_for_acknowledgement": True}
                    recent_comment |= {
                        "Acknowledged": "Description"}

                    # recent_comments.append({
                    #     "proceed_for_acknowledgement": True})
                    recent_comments.append(recent_comment)
                else:
                    recent_comments.append({
                        "proceed_for_acknowledgement": False})
                    recent_comment |= {
                        "Acknowledged": "Description"}
                # latest_comments = response.json(
                # )["comments"][-1]['body']['content']  # [0]['content']
                # jsdPublic = response.json(
                # )["comments"][-1]['jsdPublic']
            except Exception as e:
                recent_comments = None,
                logger.error("Got error in acknowledging comments: %s", e)

        else:
            print(
                f"Failed to fetch comments: {response.status_code} - {response.text}")

        return recent_comments
    except Exception as e:
        logger.error("Got error in get_issue_latest_comments function with error:%s.",
                     e)


def find_all_text_values(data):
    """
    Recursively search for all "text" values in a nested dictionary or list.
    Parameters
    ----------
    data : dict or list
        The input data structure to search through.
    Returns 
    -------
    results : list
        A list of all "text" values found in the input data.
    """
    try:
        results = []

        def search(d):
            if isinstance(d, dict):
                for key, value in d.items():
                    if key == "text":
                        results.append(value)
                    else:
                        search(value)
            elif isinstance(d, list):
                for item in d:
                    search(item)

        search(data)
        formated_results = " ".join(
            results).replace(" , ", " ")
        return formated_results
    except Exception as e:
        logger.error("Got error in find_all_text_values function with error:%s.",
                     e)
        return None


class ai_agent_services:

    def __init__(self, agent_service_input):
        self.agent_service_inputs = agent_service_input

    def jira_ticket_assignment(self):
        """
        Process a single JIRA ticket.
        """
        try:
            issue_key = self.agent_service_inputs['jira_issue']['key']
            project_key = self.agent_service_inputs['project_key']
            AI_Ticket_Assignment = "UnAssigned"
            Jira_Ticket_Note_Update = self.agent_service_inputs['Jira_Ticket_Note_Update']

            request_type = 'create_jira_tickets'
            jira_connection_details = jira_connection_object(
                request_type, project_key)
            jira_url = jira_connection_details['jira_url'] + \
                issue_key + '/assignee'
            # Assignee payload
            payload = json.dumps({
                "accountId": str(automation_account_id[1])
            })
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            auth = HTTPBasicAuth(
                jira_connection_details['username'], jira_connection_details['api_token'])
            # Make the request
            response = requests.request(
                "PUT",
                url=jira_url,
                data=payload,
                headers=headers,
                auth=auth, verify=False,
            )
            if response.status_code == 204:
                logger.info("Ticket Assigned successfully to %s",
                            issue_key)
                # print(f"Comment added successfully
                print(f"\nTicket Assigned successfully: {issue_key}")
                adding_internal_notes(
                    issue_key, project_key, Jira_Ticket_Note_Update)
                AI_Ticket_Assignment = "Assigned"
            else:
                logger.error("Failed to assign ticket: %s - %s",
                             response.status_code, response.text)
                print(
                    f"Failed to assign ticket: {response.status_code} - {response.text}")

            return AI_Ticket_Assignment

        except Exception as e:
            logger.error("Got error in jira_ticket_assignment function with error:%s.",
                         e)
            return None

    def jira_ticket_status_update(self):
        """
        Process a single JIRA ticket.
        """
        try:
            AI_Ticket_Status = [
                self.agent_service_inputs['jira_issue']['fields']['status']['name']]
            issue_key = self.agent_service_inputs['jira_issue']['key']
            project_key = self.agent_service_inputs['project_key']
            ticket_status_code = self.agent_service_inputs['Jira_Ticket_Status']
            Jira_Ticket_Note_Update = self.agent_service_inputs['Jira_Ticket_Note_Update']
            Jira_Ticket_Note_Update_Skip = self.agent_service_inputs['Jira_Ticket_Note_Update_Skip']
            request_type = 'create_jira_tickets'
            jira_connection_details = jira_connection_object(
                request_type, project_key)

            jira_url = jira_connection_details['jira_url'] + \
                issue_key + '/transitions'
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            auth = HTTPBasicAuth(
                jira_connection_details['username'], jira_connection_details['api_token'])
            # Assignee payload
            # payload = json.dumps({"transition": {"id": ticket_status,"fields": { "resolution": {"name": "Investigation completed"}, "update": {"comment": [{"add": {"body": "Resolved via API."}}]}}}})
            for status_code in ticket_status_code:
                if not Jira_Ticket_Note_Update_Skip:
                    payload = json.dumps({"transition": {"id": status_code}, "update": {"comment": [
                        {"add": {"body": {"content": [
                            {
                                "content": [
                                    {
                                        "text": Jira_Ticket_Note_Update,
                                        "type": "text"
                                    }
                                ],
                                "type": "paragraph"
                            }
                        ],
                            "type": "doc",
                            "version": 1
                        }
                        }
                        }
                    ]
                    }
                    })
                else:
                    payload = json.dumps({"transition": {"id": status_code}})

            # Make the request

                response = requests.request(
                    "POST", url=jira_url, data=payload, headers=headers, auth=auth, verify=False,)
                if response.status_code == 204:
                    logger.info("Ticket Status Updated successfully to: %s",
                                issue_key)
                    # print(f"Comment added successfully
                    print(
                        f"\nTicket {issue_key} Status Updated to: {status_code}")
                    AI_Ticket_Status.append(status_code)
                else:
                    logger.error("Failed to Update Ticket : %s - %s",
                                 response.status_code, response.text)
                    print(
                        f"Failed to Update Ticket: {response.status_code} - {response.text}")
                Jira_Ticket_Note_Update_Skip = True

            return AI_Ticket_Status

        except Exception as e:
            logger.error("Got error in jira_ticket_status_update function with error:%s.",
                         e)

    def jira_ticket_organization_update(self):
        """
        Process a single JIRA ticket.
        """
        try:
            AI_Org_Status = "Unchanged"
            issue_key = self.agent_service_inputs['jira_issue']['key']
            project_key = self.agent_service_inputs['project_key']
            Org_Code = self.agent_service_inputs['Jira_Org_Code']
            Jira_Ticket_Note_Update = self.agent_service_inputs['Jira_Ticket_Note_Update']

            request_type = 'create_jira_tickets'
            jira_connection_details = jira_connection_object(
                request_type, project_key)

            jira_url = jira_connection_details['jira_url'] + \
                issue_key

            # Payload to update the custom field
            payload = {
                "fields": {
                    # Organizations field expects an array
                    "customfield_10002": [Org_Code['id']]
                },
            }

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            auth = HTTPBasicAuth(
                jira_connection_details['username'], jira_connection_details['api_token'])
            # Make the request
            response = requests.put(
                jira_url, json=payload, headers=headers, auth=auth, verify=False)
            if response.status_code == 204:
                logger.info("Ticket Status successfully to %s",
                            issue_key)
                # print(f"Comment added successfully
                print(f"\nTicket Status Updated : {issue_key} to {Org_Code}")

                adding_internal_notes(
                    issue_key, project_key, Jira_Ticket_Note_Update)

                Org_Code |= {"Org_Set": "Success"}
                AI_Org_Status = Org_Code
            else:
                logger.error("Failed to assign ticket: %s - %s",
                             response.status_code, response.text)
                print(
                    f"Failed to assign ticket: {response.status_code} - {response.text}")
            # jira_issue['fields']['customfield_10002']
                Org_Code |= {"Org_Set": "Failed"}
                AI_Org_Status = Org_Code
            return AI_Org_Status
        except Exception as e:
            logger.error("Got error in jira_ticket_organization_update function with error:%s.",
                         e)

    def ai_recommandation_process(self):
        """
        Process a single JIRA ticket.
        """
        try:
            Ticket_Initial_Recommendation = {}
            issue = self.agent_service_inputs['jira_issue']
            issue_key = self.agent_service_inputs['jira_issue']['key']
            project_key = self.agent_service_inputs['project_key']
            jsdPublic = True
            ticket_status = self.agent_service_inputs['Jira_Ticket_Status']
            AI_Ticket_Initial_Recommendation = self.agent_service_inputs['Jira_Ticket_Note_Update']

            # disclaimer_text = "Disclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence."
            # if disclaimer_text.lower() in str(self.agent_service_inputs['Jira_Ticket_Note_Update']).lower():

            #     AI_Ticket_Initial_Recommendation = str(self.agent_service_inputs['Jira_Ticket_Note_Update']).lower().replace(disclaimer_text)
            #     # "Disclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence.", "")  # + \
            #     # "\n\n Disclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence."

            # Ticket_Initial_Recommendation |= {"Ticket_Recommendation_Status": post_latest_comments(
            #     issue, project_key, AI_Ticket_Initial_Recommendation, jsdPublic)}
            # if Ticket_Initial_Recommendation['Ticket_Recommendation_Status'] == "Recommended":
            if AI_Ticket_Initial_Recommendation:
                global agent_service_inputs
                ai_agent_service = self.agent_service_inputs['ai_agent_service']
                # agent_service_inputs |= {"Jira_Ticket_Status": "271"}
                Ticket_Initial_Recommendation |= {
                    "Ticket_Status_After_Recommendation": ai_agent_service.jira_ticket_status_update()}
                logger.info("Ticket Status changed to %s for the Ticket number: %s",
                            ticket_status, issue_key)
                # print(f"Comment added successfully
                print(
                    f"\nTicket Status changed to {ticket_status} for the Ticket number: {issue_key}")

            return Ticket_Initial_Recommendation
        except Exception as e:
            logger.error("Got error in ai_recommandation_process function with error:%s.",
                         e)
            return None

    def ai_based_recommendation(self):
        """
        Process a single JIRA ticket.
        """
        try:
            global agent_service_inputs
            escalate_to_l2 = False
            ticket_current_status = self.agent_service_inputs['jira_issue']['fields']['status']['name']
            agent_service_inputs |= {"Jira_Ticket_Note_Update_Skip": False}
            ai_recommendation_status = {
                "AI_Generated_Recommendation": None,
                "AI_Recommendation_Status": "Unable to Recommend by OpenAI LLM",
                "Ticket_Status_After_Recommendation": None,
                "AI_Recommendation_Raw_Output": "No AI Recommendation",

            }
            ticket_complete_info = self.agent_service_inputs['ticket_complete_info']
            qna_or_comment_classify = self.agent_service_inputs['qna_or_comment_classify']
            restricted_info = {"Plant name": "",
                               "Source IP": "",
                               "Destination IP": "",
                               "Source Host": "",
                               "Destination Host": "",
                               "source MAC": "",
                               "Destination MAC": "",
                               "Computer Name": "",
                               "Domain Name": "",
                               "User Name": "",
                               "IP Address": "",
                               "hostname": "",
                               "Source Domain": "",
                               "Machine IP": "",
                               "Machine Name": "",
                               }

            # Normalize text for matching
            normalized_text = ticket_complete_info.lower()

            # skip if the last comments/ description has "It's an AI-powered L1 Agent's Transcript"
            if "it's an ai-powered l1 agent's transcript" in normalized_text:
                return None

            # Step 1: Extract values and update dictionary
            for key in restricted_info:
                key_clean = key.strip().lower()
                pattern = rf"{re.escape(key_clean)}:\s*(.+)"
                match = re.search(pattern, normalized_text)
                if match:
                    value = match.group(1).strip().split(" ")[0]
                    restricted_info[key] = value
                    # Replace original value in the original text (case-sensitive)
                    original_pattern = rf"{re.escape(key)}:\s*{re.escape(value)}"
                    ticket_complete_info = re.sub(
                        original_pattern, f"{key}: {key}_placeholder", ticket_complete_info)
                    ticket_complete_info = ticket_complete_info.replace(
                        value, key+"_placeholder")

            # Step 2: Validate with LLM for Comparing with known use case names.
            def process_requests_openai(restricted_info, ticket_complete_info, question):
                """
                This Function tries to process OpenAI requests.
                Parameters
                ----------
                None.
                Returns
                -------
                None.
                """
                try:
                    context_prompt = create_openai_prompt(
                        restricted_info, ticket_complete_info, qna_or_comment_classify)
                    translated_text = generate_openai_completion(
                        context_prompt, question, qna_or_comment_classify)

                    return translated_text
                except Exception as e:
                    logger.error("Got error in process_requests_openai function with error:%s.",
                                 e)

            if ticket_complete_info:
                # "Based on the attached alert details, please answer my question as a SOC Analyst."
                question = self.agent_service_inputs['question_to_ai']
                ai_recommendation = process_requests_openai(
                    restricted_info, ticket_complete_info, question)
            # Step 3: validate the ai_recommendation and take action based on that. Example -  if KNOWN_ACTIVITY then proceed for closure else escalate to L2.
            if ai_recommendation == 'KNOWN_ACTIVITY':
                ai_comments = "Based on the obtained details, the activity has been identified as a 'Known Activity' and Proceeding with the closure of the ticket." + \
                    "\n\n" + "Disclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence."
                agent_service_inputs |= {"Jira_Ticket_Status": [str(
                    ticket_status_codes["Waiting_For_Customer_To_Resolved"])]}

            elif ai_recommendation in ['UNKNOWN_ACTIVITY', 'UNSURE_BY_AI_AGENT']:
                escalate_to_l2 = True
                ai_comments = "Based on the obtained details, the activity has been identified as a 'UnKnown Activity' and Proceeding with the Escalation to L2 for Further investigation of the ticket." + \
                    "\n\n" + "Disclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence."
                if ticket_current_status == "Waiting for Customer":
                    agent_service_inputs |= {"Jira_Ticket_Status": [str(
                        ticket_status_codes["Waiting_For_Customer_To_Work_In_Progress"]),
                        str(
                        ticket_status_codes["Work_In_Progress_To_Work_In_Progress_By_L2"])]}

                elif ticket_current_status == "Work In Progress":
                    agent_service_inputs |= {"Jira_Ticket_Status": [str(
                        ticket_status_codes["Work_In_Progress_To_Work_In_Progress_By_L2"])]}
                # Waiting_For_Customer_To_Work_In_Progress_By_L2  Work_In_Progress_To_Work_In_Progress_By_L2
            elif ai_recommendation == None or ai_recommendation.strip() == "":
                logger.error("AI LLM Unable to provide any recommendation for the ticket: %s with comments/description: %s",
                             self.agent_service_inputs['jira_issue']['key'], normalized_text)
                escalate_to_l2 = True
                ai_comments = "Based on the obtained details, AI LLM Agent is Unable to provide any recommendation for the ticket and Proceeding with the Escalation to L2 for Further investigation of the ticket." + \
                    "\n\n" + "Disclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence."
                if ticket_current_status == "Waiting for Customer":
                    agent_service_inputs |= {"Jira_Ticket_Status": [str(
                        ticket_status_codes["Waiting_For_Customer_To_Work_In_Progress"]),
                        str(
                        ticket_status_codes["Work_In_Progress_To_Work_In_Progress_By_L2"])]}

                elif ticket_current_status == "Work In Progress":
                    agent_service_inputs |= {"Jira_Ticket_Status": [str(
                        ticket_status_codes["Work_In_Progress_To_Work_In_Progress_By_L2"])]}

            elif ai_recommendation:
                agent_service_inputs |= {"Jira_Ticket_Status": [str(
                    ticket_status_codes["Work_In_Progress_To_Waiting_For_Customer"])]}
                split_complete_recommendation = ai_recommendation.split(
                    "Disclaimer:")

                ai_comments = split_complete_recommendation[0].strip()
            # Step 4: Extract values and update dictionary. Then replace placeholders with actual values.

                for key in restricted_info:
                    key_clean = key.strip().lower()
                    if key_clean+"_placeholder" in ai_comments.lower() or key_clean in ai_comments.lower():
                        ai_comments = ai_comments.lower().replace(
                            key_clean+"_placeholder", restricted_info[key])
                        ai_comments = ai_comments.lower().replace(
                            key_clean, restricted_info[key])
                ai_comments = ai_comments + "\n\n" + "Disclaimer: " + \
                    split_complete_recommendation[1].strip()
                # ai_recommendation = re.sub(original_pattern, f"{key}_placeholder: {key}", ai_recommendation)
                # pattern = rf"{re.escape(key_clean)}:\s*(.+)"
                # match = re.search(pattern, normalized_text)
                # if match:
                #     value = match.group(1).strip().split(" ")[0]
                #     restricted_info[key] = value
                #     # Replace original value in the original text (case-sensitive)
                #     original_pattern = rf"{re.escape(key)}:\s*{re.escape(value)}"
                #     ticket_complete_info = re.sub(original_pattern, f"{key}: {key}+_placeholder", ticket_complete_info)
                #     ticket_complete_info = ticket_complete_info.replace(value,key_clean+"_placeholder")

            # Update the ai_comments to JIRA ticket using REST API.
            if ai_comments:
                ai_agent_service = self.agent_service_inputs['ai_agent_service']
                # global agent_service_inputs
                agent_service_inputs |= {"Jira_Ticket_Note_Update": str(
                    ai_comments)}
                # agent_service_inputs |= {
                #     "ai_recommandation": ai_comments}
                agent_service_inputs |= {
                    "escalate_to_l2": escalate_to_l2}
                usecase_recommendation = ai_agent_service.ai_recommandation_process()
            # if usecase_recommendation['Ticket_Recommendation_Status'] == "Recommended":
                ai_recommendation_status |= {
                    "AI_Generated_Recommendation": ai_comments}
                ai_recommendation_status |= {
                    "AI_Recommendation_Status": "Recommended by OpenAI LLM"}
                ai_recommendation_status |= {
                    "Ticket_Status_After_Recommendation": usecase_recommendation['Ticket_Status_After_Recommendation']}
                ai_recommendation_status |= {
                    "AI_Recommendation_Raw_Output": ai_recommendation}
            # else:
            #     ai_recommendation_status |= {
            #         "AI_Generated_Recommendation": None}
            #     ai_recommendation_status |= {
            #         "AI_Recommendation_Status": "Unable to Recommend by OpenAI LLM"}
            #     ai_recommendation_status |= {
            #         "Ticket_Status_After_Recommendation": None}
            #     ai_recommendation_status |= {
            #         "escalate_to_l2": escalate_to_l2}

            ai_recommendation_status |= {
                "escalate_to_l2": escalate_to_l2}
            return ai_recommendation_status
        except Exception as e:
            logger.error("Got error in ai_based_recommendation function with error:%s.",
                         e)
            return "Failed to Recommend by OpenAI LLM"


def adding_internal_notes(issue_key, project_key, Jira_Ticket_Note_Update):
    try:
        request_type = 'create_jira_tickets'
        jira_connection_details = jira_connection_object(
            request_type, project_key)
        url = jira_connection_details['jira_url'] + \
            issue_key + '/comment'
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        auth = HTTPBasicAuth(
            jira_connection_details['username'], jira_connection_details['api_token'])

        payload = json.dumps({
            "body": {
                "content": [
                    {
                        "content": [
                            {
                                "text": Jira_Ticket_Note_Update,
                                "type": "text"
                            }
                        ],
                        "type": "paragraph"
                    }
                ],
                "type": "doc",
                "version": 1
            },

        })
        response = requests.request(
            "POST",
            url,
            data=payload,
            headers=headers,
            auth=auth, verify=False
        )
        if response.status_code == 201:
            logger.info("Comment added to Ticket after Organization Updated successfully to %s",
                        issue_key)
            # print(f"Comment added successfully
            print(f"\nTicket Status Updated : {issue_key}")
    except Exception as e:
        logger.error("Got error in adding_internal_notes function with error:%s.",
                     e)


def get_jira_ticket_details(es_issue, project_key, method_called_from):
    """Get JIRA ticket details.

    Args:
        issue (bool): _description_
        project_key (_type_): _description_
    """
    try:
        request_type = 'create_jira_tickets'
        jira_connection_details = jira_connection_object(
            request_type, project_key)

        if method_called_from in ['AI_Ticket_Assignment', 'AI_Ticket_Status_Update', 'AI_Ticket_Org_Update']:
            jira_url = jira_connection_details['jira_url'] + es_issue["key"]
        elif method_called_from in ['ai_l1_processing_agent_operations']:
            jira_url = jira_connection_details['jira_url'] + es_issue["_id"]

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        auth = HTTPBasicAuth(
            jira_connection_details['username'], jira_connection_details['api_token'])
        # Make the request
        response = requests.request(
            "GET",
            url=jira_url,
            headers=headers,
            auth=auth, verify=False,
        )

        if response.status_code == 200:

            jira_issue = json.loads(response.text)
        else:
            logger.error("Failed to assign ticket: %s - %s",
                         response.status_code, response.text)
            print(
                f"Failed to assign ticket: {response.status_code} - {response.text}")
            jira_issue = None
        return jira_issue
    except Exception as e:
        logger.error("Got error in get_jira_ticket_details function with error:%s.",
                     e)
        return None


def AI_Ticket_Assignment(ai_agent_service, jira_issue, project_key):
    """
    This Function tries to assign JIRA tickets to Automation account.
    Parameters
    ----------
    None.
    Returns
    -------
    None.
    """
    try:
        ticket_assignment_details = {}
        global agent_service_inputs
        if jira_issue['fields']['assignee'] is None:
            agent_service_inputs |= {
                "Assign_Jira_Ticket_To": account_ids["ITOTSOC-24-027-AutoAlerts"], }
            agent_service_inputs |= {"Jira_Ticket_Note_Update": str(
                f"Status of the ticket changed, 'Ticket Assigned to {list(Jira_Account_ID['PTT_Dev'].keys())[0]}' by AI Processing L1 Agent "
                f"\n\nDisclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence.")}
            AI_Ticket_Assignment_Status = ai_agent_service.jira_ticket_assignment()
            jira_issue = get_jira_ticket_details(
                jira_issue, project_key, "AI_Ticket_Assignment")
            ticket_assignment_details |= {
                "Ticket_Assignment_Status": AI_Ticket_Assignment_Status,
                "Ticket_Assigned_To_ID": jira_issue['fields']['assignee']['accountId'],
                "Ticket_Assigned_To_Name": jira_issue['fields']['assignee']['displayName']}
        elif jira_issue['fields']['assignee']['accountId'] == account_ids["ITOTSOC-24-027-AutoAlerts"]:
            ticket_assignment_details |= {
                "Ticket_Assignment_Status": "Already_Assigned",
                "Ticket_Assigned_To_ID": jira_issue['fields']['assignee']['accountId'],
                "Ticket_Assigned_To_Name": jira_issue['fields']['assignee']['displayName']}
        # else:
        #     AI_Ticket_Assignment_Status = ai_agent_service.jira_ticket_assignment()
        #     jira_issue = get_jira_ticket_details(jira_issue, project_key,"AI_Ticket_Assignment")
        #     ticket_assignment_details |= {
        #         "Ticket_Assignment_Status": AI_Ticket_Assignment_Status,
        #         "Ticket_Assigned_To_ID": jira_issue['fields']['assignee']['accountId'],
        #         "Ticket_Assigned_To_Name": jira_issue['fields']['assignee']['displayName']}

        return ticket_assignment_details
    except Exception as e:
        logger.error("Got error in AI_Ticket_Assignment function with error:%s.",
                     e)


def AI_Ticket_Status_Update(ai_agent_service, jira_issue, project_key):
    """
    This Function tries to assign JIRA tickets to Automation account.
    Parameters
    ----------
    None.
    Returns
    -------
    None.
    """
    try:
        ticket_status_details = {}

        Jira_Ticket_Status = jira_issue['fields']['status']['name']
        global agent_service_inputs
        agent_service_inputs |= {"Jira_Ticket_Note_Update_Skip": False}
        if Jira_Ticket_Status == "Open":
            agent_service_inputs |= {"Jira_Ticket_Status": [str(
                ticket_status_codes["Open_To_Work_In_Progress"])]}
            agent_service_inputs |= {"Jira_Ticket_Note_Update": str(
                "Status of the ticket changed to 'Work In Progress' by AI Processing L1 Agent"
                                     f"\n\nDisclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence.")}

            AI_Ticket_Status_Update = ai_agent_service.jira_ticket_status_update()
            jira_issue = get_jira_ticket_details(
                jira_issue, project_key, "AI_Ticket_Status_Update")
            ticket_status_details |= {
                "Ticket_Assignment_Status": AI_Ticket_Status_Update,
                # jira_issue['fields']['assignee']['accountId'],
                "Ticket_Status_Updated_By": "AI Processing Agent",
                "Ticket_Status_Updated_By_Account_ID": jira_issue['fields']['assignee']['accountId'],
                "Ticket_Status_Updated_By_Name": jira_issue['fields']['assignee']['displayName']
            }
        elif Jira_Ticket_Status != "Open":
            ticket_status_details |= {
                "Ticket_Assignment_Status": "Already_In_Progress",
                "Ticket_Status_Updated_By_Account_ID": jira_issue['fields']['assignee']['accountId'],
                "Ticket_Status_Updated_By_Name": jira_issue['fields']['assignee']['displayName']
            }

        return ticket_status_details
    except Exception as e:
        logger.error("Got error in AI_Ticket_Status_Update function with error:%s.",
                     e)


def AI_Ticket_Organization_Update(ai_agent_service, jira_issue, project_key):
    """
    This Function tries to assign JIRA tickets to Automation account.
    Parameters
    ----------
    None.
    Returns
    -------
    None.
    """
    try:
        ticket_status_details = {}
        """
        Organization is a custom field in JIRA. Hence need to check with JIRA admin to get the custom field id before 
        updating the same.
        Example : For PTT Dev - customfield_10002 is the custom field id for Organization field.
        and "YIL" is the Organization value available for PTT Dev project.
                                
        """
        global agent_service_inputs
        ticket_status_details = {}
        if not jira_issue['fields']['customfield_10002']:
            agent_service_inputs |= {
                "Jira_Org_Code": ticket_Org_codes[project_key][0]}
            agent_service_inputs |= {"Jira_Ticket_Note_Update": str(
                f"Status of the ticket changed, Organization to '{ticket_Org_codes[project_key][0]['name']}' by AI Processing L1 Agent"
                f"\n\nDisclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence.")}

            AI_Ticket_Org_Update = ai_agent_service.jira_ticket_organization_update()
            jira_issue = get_jira_ticket_details(
                jira_issue, project_key, "AI_Ticket_Org_Update")
            Jira_Ticket_Org_Status = jira_issue['fields']['customfield_10002'][0]['name']
            # agent_service_inputs |= {"Jira_Ticket_Note_Update": str(
            #     f"Status of the ticket changed, Organization to '{Jira_Ticket_Org_Status}' by AI Processing L1 Agent"
            #     f"\n\nDisclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence.")}

            ticket_status_details |= {
                "Ticket_Org_Status": AI_Ticket_Org_Update,
                # jira_issue['fields']['assignee']['accountId'],
                "Ticket_Org_Status_Updated_By": "AI Processing Agent",
                "Ticket_Organization": Jira_Ticket_Org_Status,
                "Ticket_Org_Status_Updated_By_Account_ID": jira_issue['fields']['assignee']['accountId'],
                "Ticket_Org_Status_Updated_By_Name": jira_issue['fields']['assignee']['displayName']
            }
        else:
            Jira_Ticket_Org_Status = jira_issue['fields']['customfield_10002'][0]['name']
            ticket_status_details |= {
                "Ticket_Org_Status": "Org_Already_Assigned",
                "Ticket_Organization": Jira_Ticket_Org_Status,
                "Ticket_Org_Status_Updated_By_Account_ID": jira_issue['fields']['assignee']['accountId'],
                "Ticket_Org_Status_Updated_By_Name": jira_issue['fields']['assignee']['displayName']
            }

        return ticket_status_details
    except Exception as e:
        logger.error("Got error in AI_Ticket_Organization_Update function with error:%s.",
                     e)


def AI_Usecase_Knowledge_Comparison(
        ai_agent_service, jira_issue, project_key):
    """
    This Function tries to interpret the ticket summary/desrciption to known or unknown uecase by comparing
    the scoped usecase for PTT and provide recommadations. 
    """
    try:
        global agent_service_inputs
        ticket_status_details = {}
        agent_service_inputs |= {"Jira_Ticket_Note_Update_Skip": False}
        # 1. Load the usecase knowledge base
        ptt_usecases_data = json.load(open('ptt_use_cases.json'))
        usecase_knowledge_base = []

        for section in ptt_usecases_data.values():
            for item in section:
                name = item.get("Use case Name")
                if name:
                    usecase_knowledge_base.append(name)

        # 2. Extract text from summary and description
        summary_text = jira_issue['fields']['summary']
        description_text = find_all_text_values(
            jira_issue['fields']['description']) if jira_issue['fields']['description'] else ""

        combined_text = f"{summary_text} {description_text}"

        # 3. Compare with usecase knowledge base
        matched_usecases = []
        # usecase for usecase in usecase_knowledge_base if usecase.lower() in combined_text.lower()]

        def find_matching_objects(data, target_value):
            matches = []

            def search(obj):
                if isinstance(obj, dict):
                    if target_value in obj.values():
                        matches.append(obj)
                    for value in obj.values():
                        search(value)
                elif isinstance(obj, list):
                    for item in obj:
                        search(item)

            search(data)
            return matches

        if matched_usecases:
            default_usecase = find_matching_objects(
                ptt_usecases_data, matched_usecases[0])
            # global agent_service_inputs
            if default_usecase:

                agent_service_inputs |= {
                    "ai_recommandation": default_usecase[0]['Default Recommendations']}
                # agent_service_inputs |= {
                #     "ai_recommandation": 271}
                usecase_recommendation = ai_agent_service.ai_recommandation_process()
                ticket_status_details |= {
                    "Usecase_Knowledge_Status": "Known_Usecase",
                    "Usecase_Recommendation_Status": "Recommended",
                    "Matched_Usecases": matched_usecases,
                    "Usecase_Knowledge_Compared_By": "AI Processing Agent L1"
                }
                ticket_status_details |= {
                    "Ticket_Status_After_Recommendation": usecase_recommendation['Ticket_Status_After_Recommendation']}
        else:
            qna_or_comment_classify = "QNA"
            question = """Based on the attached alert details, please answer my question as a SOC Analyst.
                        And revert your answer as with following sample example format. Dont mimic asis, and dont append text like here is your formated etc. Give the straight away answer only. 
                        
                        "Use case Name": "New Conflict Asset",
                        "Detection": "Alert/New Conflict Asset",
                        "Mitre ID": "Lateral Movement",
                        "Log sources": "CTD",
                        "Default Recommendations": "Recommendation Actions:\n1. Check the host behind the IP address from where new asset detected.\n2. Block the host MAC address/IP on firewall if the host IP is external, so that the rouge asset can not able to connect to the network.",
                        "Priority (In JIRA)": "Medium"
                        
                        Please dont mention that 
            
                        """
            agent_service_inputs |= {
                "ticket_complete_info": combined_text}
            agent_service_inputs |= {
                "question_to_ai": question}
            agent_service_inputs |= {
                "qna_or_comment_classify": qna_or_comment_classify}

            usecase_interpretation = ai_agent_service.ai_based_recommendation()

            ticket_status_details |= {
                "Usecase_Knowledge_Status": "Unknown_Usecase",
                "UnMatched_Usecases": summary_text,
                "Usecase_Recommendation_Status": usecase_interpretation['AI_Recommendation_Status'],
                "Usecase_Knowledge_Compared_By": "AI LLM"
            }
            ticket_status_details |= {
                "Ticket_Status_After_Recommendation": None}
        return ticket_status_details
    except Exception as e:
        logger.error("Got error in AI_Usecase_Knowledge_Comparison function with error:%s.",
                     e)


def AI_Recent_Comments_Interpretation(
        ai_agent_service, jira_issue, project_key):
    """
    This Function tries to interpret the customer comments on JIRA tickets.
    """
    try:
        global agent_service_inputs
        ticket_all_comments = jira_issue['fields']['comment']['comments']

        ticket_status_details = {
            "Customer_Comments_Interpretation": "Not_Processed_Yet",
            "AI_Recommendation_Raw_Output": "Not_Processed_Yet",
            "Escalate_To_L2": False,
            "Ticket_Status_After_Recommendation": "Not_Processed_Yet"
        }

        if ticket_all_comments:
            # for comment in ticket_all_comments:
            comment_body = find_all_text_values(
                ticket_all_comments[-1]['body'])  # comment['body'])
            last_comment_updated_by = ticket_all_comments[-1]['updateAuthor']['accountId']
            if comment_body:
                if last_comment_updated_by in [account_ids["Koushik"], account_ids["Koushik"]] and jira_issue['fields']['status']['name'] == 'Work in progress':
                    ai_comments = comment_body
                    agent_service_inputs |= {"Jira_Ticket_Note_Update": str(
                        ai_comments)}
                    agent_service_inputs |= {
                        "Jira_Ticket_Note_Update_Skip": True}

                    agent_service_inputs |= {"Jira_Ticket_Status": [str(
                        ticket_status_codes["Work_In_Progress_To_Waiting_For_Customer"])]}
                    AI_Ticket_Status_Update = ai_agent_service.jira_ticket_status_update()

                    if AI_Ticket_Status_Update:
                        ticket_status_details = {
                            "L2_Comments_Notified_To_Customer": True,
                            "Escalate_To_L2": False,
                            "Ticket_Status_After_Recommendation": "Customer_Not_Yet_Commented"
                        }
                elif "Disclaimer: It's an AI".lower() in comment_body.lower():
                    ticket_status_details = {
                        "Customer_Comments_Interpretation": "Customer_Not_Yet_Commented",
                        "AI_Recommendation_Raw_Output": "Customer_Not_Yet_Commented",
                        "Escalate_To_L2": False,
                        "Ticket_Status_After_Recommendation": "Customer_Not_Yet_Commented"
                    }
                    # continue
                else:
                    question = "Please understand the customer comments and classify as 'KNOWN_ACTIVITY' or 'UNKNOWN_ACTIVITY' from the attached alert details. Reply only 'KNOWN_ACTIVITY' (In Capital casing). Iif you could interpret as known activity else if you could interpret as unknown activity reply with 'UNKNOWN_ACTIVITY' (In Capital casing). Be strict with the interpretation process, if you are unsure please reply as 'UNSURE_BY_AI_AGENT' (In Capital casing)."
                    qna_or_comment_classify = "Comment_Classification"

                    agent_service_inputs |= {
                        "ticket_complete_info": comment_body}
                    agent_service_inputs |= {
                        "question_to_ai": question}
                    agent_service_inputs |= {
                        "qna_or_comment_classify": qna_or_comment_classify}
                    usecase_interpretation = ai_agent_service.ai_based_recommendation()
                    if usecase_interpretation:
                        print(usecase_interpretation)
                        print(f"\nCustomer Comment: {comment_body}")
                        ticket_status_details |= {
                            "Customer_Comments_Interpretation": usecase_interpretation['AI_Recommendation_Status'],
                            "AI_Recommendation_Raw_Output": usecase_interpretation['AI_Recommendation_Raw_Output'],
                            "Escalate_To_L2": usecase_interpretation['escalate_to_l2'],

                        }
                        ticket_status_details |= {
                            "Ticket_Status_After_Recommendation": usecase_interpretation['Ticket_Status_After_Recommendation']}
                # Process the comment body with AI LLM for interpretation
                # You can implement similar logic as in ai_based_recommendation
                # to interpret the comment and take necessary actions.

        return ticket_status_details
    except Exception as e:
        logger.error("Got error in AI_Recent_Comments_Interpretation function with error:%s.",
                     e)


def AI_Ticket_Status_Resolution(ai_agent_service, jira_issue, project_key):
    """
    This Function tries to change the status of ticket to resolve and close.
    Parameters
    ----------
    None.
    Returns
    -------
    None.
    """
    try:
        ticket_status_details = {}
        ticket_next_stage = None
        global agent_service_inputs
        agent_service_inputs |= {"Jira_Ticket_Note_Update_Skip": False}
        ticket_last_updated_at = datetime.datetime.strptime(
            jira_issue['fields']['updated'].split(".")[0].replace("T", " "), "%Y-%m-%d %H:%M:%S")
        current_asia_bangkok_time = datetime.datetime.strptime(str(datetime.datetime.now(
            pytz.timezone('Asia/Bangkok'))).split(".")[0], "%Y-%m-%d %H:%M:%S")

        # Calculate the time difference
        buffer_time_to_close_ticket = abs(
            current_asia_bangkok_time - ticket_last_updated_at)

        # Check if the difference is greater than 12 hours, if yes then close the ticket else skip
        if buffer_time_to_close_ticket > timedelta(seconds=10):
            ticket_next_stage = "Closed"
            logger.info("The difference is greater than 12 hours for the ticket: %s. Hence proceeding to close the ticket.",
                        jira_issue['key'])
            print(
                "The difference is greater than 12 hours. Hence proceeding to close the ticket.")
        else:
            ticket_next_stage = "Resolved"
            logger.info("The difference is Less than 12 hours for the ticket: %s. Hence Not proceeding to close the ticket.",
                        jira_issue['key'])
            print(
                "The difference is NOT greater than 12 hours. Hence Not proceeding to close the ticket.")

        ai_resolution_comments = f"The Status of the ticket changed to '{ticket_next_stage}' by AI Processing L1 Agent." + \
            "\n\n" + "Disclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence."

        if ticket_next_stage == "Closed":
            agent_service_inputs |= {"Jira_Ticket_Status": [str(
                ticket_status_codes["Resolved_To_Closed"])]}
            agent_service_inputs |= {"Jira_Ticket_Note_Update": str(
                ai_resolution_comments)}
            AI_Ticket_Status_Update = ai_agent_service.jira_ticket_status_update()
            jira_issue = get_jira_ticket_details(
                jira_issue, project_key, "AI_Ticket_Status_Update")
            if jira_issue['fields']['status']['name'] == "Closed":
                issue_key = jira_issue['key']
                adding_internal_notes(
                    issue_key, project_key, ai_resolution_comments)
                ticket_status_details |= {
                    "Ticket_Closure_Status": jira_issue['fields']['status']['name'],
                    "Ticket_Status_Updated_By": "L1 AI Processing Agent",
                    "Ticket_Status_Updated_By_Account_ID": jira_issue['fields']['assignee']['accountId'],
                    "Ticket_Status_Updated_By_Name": jira_issue['fields']['assignee']['displayName']
                }
            else:
                ticket_status_details |= {
                    "Ticket_Closure_Status": "Unable_To_Close_Yet_Resolved",
                    "Ticket_Status_Updated_By": "L1 AI Processing Agent",
                    "Ticket_Status_Updated_By_Account_ID": jira_issue['fields']['assignee']['accountId'],
                    "Ticket_Status_Updated_By_Name": jira_issue['fields']['assignee']['displayName']
                }
        else:  # ticket_next_stage == "Resolved":
            ticket_status_details |= {
                "Ticket_Closure_Status": "Resolved_Yet_Closed",
                "Ticket_Status_Updated_By": "L1 AI Processing Agent",
                "Ticket_Status_Updated_By_Account_ID": jira_issue['fields']['assignee']['accountId'],
                "Ticket_Status_Updated_By_Name": jira_issue['fields']['assignee']['displayName']
            }

        return ticket_status_details
    except Exception as e:
        logger.error("Got error in AI_Ticket_Status_Resolution function with error:%s.",
                     e)


def ai_l1_processing_agent_operations(es_all_issues, project_key):
    """
    This Function tries to process JIRA tickets information and push them into Elastic Search.
    Parameters
    ----------
    es_all_issues : List Object.
        DESCRIPTION: Holds the JIRA tickets information.
    project_key : String Object.
        DESCRIPTION: Holds the JIRA project key.

    Returns
    -------
    None.
    """
    try:
        if not es_all_issues:
            logger.info(
                "No JIRA tickets found for project: %s by AI processing Agent L1", project_key)
            return
        ai_agent_l1_tickets = []

        test_issue = ['SOC24027D-292433']#'SOC24027D-292419']  # ,'SOC24027D-269305',

        for es_issue in es_all_issues:
            ai_agent_l1_text_dict = {}
            ai_agent_l1_text_dict |= {"Issue_Key": es_issue['_id']}

            if es_issue['_id'] in test_issue:
                jira_issue = get_jira_ticket_details(
                    es_issue, project_key, "ai_l1_processing_agent_operations")

                global agent_service_inputs
                agent_service_inputs |= {"jira_issue": jira_issue,
                                         "project_key": project_key}
                ai_agent_service = ai_agent_services(agent_service_inputs)
                agent_service_inputs |= {
                    "ai_agent_service": ai_agent_service, }
                # , 'Work in progress']:
                if jira_issue['fields']['status']['name'] in ['Open']:
                    # 1. Ticket Assignment
                    ticket_processing_details = AI_Ticket_Assignment(
                        ai_agent_service, jira_issue, project_key)
                    if ticket_processing_details:
                        ai_agent_l1_text_dict |= ticket_processing_details
                    else:
                        ai_agent_l1_text_dict |= {
                            "Ticket_Processing_Status": "AI_Ticket_Assignment_Failed"}
                        ai_agent_l1_tickets.append(ai_agent_l1_text_dict)
                    # 2. Update Ticket Status
                    ticket_processing_details = AI_Ticket_Status_Update(
                        ai_agent_service, jira_issue, project_key)
                    if ticket_processing_details:
                        ai_agent_l1_text_dict |= ticket_processing_details
                    else:
                        ai_agent_l1_text_dict |= {
                            "Ticket_Processing_Status": "AI_Ticket_Status_Update_Failed"}
                        ai_agent_l1_tickets.append(ai_agent_l1_text_dict)

                    # 3. Update Ticket Organization
                    ticket_processing_details = AI_Ticket_Organization_Update(
                        ai_agent_service, jira_issue, project_key)
                    if ticket_processing_details:
                        ai_agent_l1_text_dict |= ticket_processing_details
                    else:
                        ai_agent_l1_text_dict |= {
                            "Ticket_Processing_Status": "AI_Ticket_Organization_Update_Failed"}
                        ai_agent_l1_tickets.append(ai_agent_l1_text_dict)

                    # 4. Compare with Usecase Knowledge and # 5. Generate Recommendations
                    ticket_processing_details = AI_Usecase_Knowledge_Comparison(
                        ai_agent_service, jira_issue, project_key)
                    if ticket_processing_details:
                        ai_agent_l1_text_dict |= ticket_processing_details
                    else:
                        ai_agent_l1_text_dict |= {
                            "Ticket_Processing_Status": "AI_Ticket_Usecase_Knowledge_Comparison_Failed"}
                        ai_agent_l1_tickets.append(ai_agent_l1_text_dict)

                elif jira_issue['fields']['status']['name'] in ['Work in progress', 'Waiting for Customer']:

                    # 5. Customer Comments Interpretation 6. Ticket Escalation to L2
                    ticket_processing_details = AI_Recent_Comments_Interpretation(
                        ai_agent_service, jira_issue, project_key)
                    if ticket_processing_details:
                        ai_agent_l1_text_dict |= ticket_processing_details
                    else:
                        ai_agent_l1_text_dict |= {
                            "Ticket_Processing_Status": "AI_Recent_Comments_Interpretation_Failed"}
                        ai_agent_l1_tickets.append(ai_agent_l1_text_dict)

                elif jira_issue['fields']['status']['name'] in ['Resolved']:

                    # 7. Ticket Resolution
                    ticket_processing_details = AI_Ticket_Status_Resolution(
                        ai_agent_service, jira_issue, project_key)
                    if ticket_processing_details:
                        ai_agent_l1_text_dict |= ticket_processing_details
                    else:
                        ai_agent_l1_text_dict |= {
                            "Ticket_Processing_Status": "AI_Ticket_Status_Resolution_Failed"}
                        ai_agent_l1_tickets.append(ai_agent_l1_text_dict)
                else:
                    ai_agent_l1_text_dict |= {
                        "Ticket_Processing_Status": "No_Actions_Taken_By_L1_AI_Processing_Agent"
                    }
                    ai_agent_l1_tickets.append(ai_agent_l1_text_dict)

                if "gsp4" in jira_issue['fields']['summary'].lower():
                    ai_agent_l1_text_dict |= {
                        "Custom_Field_Plant_ID": "PTT-GSP4"}
                elif "gsp7" in jira_issue['fields']['summary'].lower():
                    ai_agent_l1_text_dict |= {
                        "Custom_Field_Plant_ID": "PTT-GSP7"}
                elif "rayong" in jira_issue['fields']['summary'].lower():
                    ai_agent_l1_text_dict |= {
                        "Custom_Field_Plant_ID": "PTT-RAYONG"}
                else:
                    ai_agent_l1_text_dict |= {
                        "Custom_Field_Plant_ID": "PTT-Other_Plants"}

            ai_agent_l1_text_dict |= {
                # comment this for production.
                "Custom_Field_Plant_ID": "PTT-Other_Plants"}
            ai_agent_l1_text_dict |= {
                "Ticket_Processing_Status": "No_Actions_Taken_By_L1_AI_Processing_Agent"
            }
            ai_agent_l1_tickets.append(ai_agent_l1_text_dict)
        # print(ai_agent_l1_tickets)
        return ai_agent_l1_tickets
    except Exception as e:
        logger.error("Got error in ai_l1_processing_agent_operations function with error:%s.",
                     e)


def filter_plant_based_issues(processed_data):
    """
    This Function filters JIRA issues based on the provided plant ID.
    Parameters
    ----------
    all_issues : List Object.
    plant_id : String Object.
    Returns
    -------
    filtered_issues : List of Dictionaries.

    """
    try:
        filtered_issues = {"ptt_gsp4_issues": [], "ptt_gsp7_issues": [
        ], "ptt_rayong_issues": [], "ptt_other_plants": []}
        # ptt_gsp4_issues,ptt_gsp7_issues,ptt_rayong = [],[],[]
        for issue in processed_data:

            if issue['Custom_Field_Plant_ID'] == "PTT-GSP4":
                filtered_issues["ptt_gsp4_issues"].append(issue)
            elif issue['Custom_Field_Plant_ID'] == "PTT-GSP7":
                filtered_issues["ptt_gsp7_issues"].append(issue)
            elif issue['Custom_Field_Plant_ID'] == "PTT-RAYONG":
                filtered_issues["ptt_rayong_issues"].append(issue)
            else:
                filtered_issues["ptt_other_plants"].append(issue)

        #     if 'customfield_10216' in issue['fields'] and issue['fields']['customfield_10216'] == plant_id:
        #         filtered_issues.append(issue)
        return filtered_issues
    except Exception as e:
        logger.error("Got error in filter_plant_based_issues function with error:%s.",
                     e)


def bulk_push_to_elastic(index_doc_mapper, conn_es):
    """
    This Function tries to push data into Elastic Search Index.
    Parameters
    ----------
    index_doc_mapper : List of Dictionaries.
        DESCRIPTION: Holds the data to be pushed into Elastic Search Index.
    conn_es : Elastic Search Connection Object.
        DESCRIPTION: Holds the Elastic Search connection object.

    Returns
    -------
    success, failed : Tuple Object.
        DESCRIPTION: Holds the success and failed count of documents pushed into Elastic Search Index.

    """
    try:
        success, failed = helpers.bulk(conn_es, index_doc_mapper)
        if success:
            logger.info("Successfully pushed %s documents to Elastic Search Index.",
                        success)
            return success
        elif failed:
            logger.error("Failed to push %s documents to Elastic Search Index.",
                         failed)
            return failed
    except Exception as e:
        logger.error("Got error in bulk_push_to_elastic function with error:%s.",
                     e)


def export_to_elastic(final_dump_into_elastic, project_key):
    """
    This Function tries to export collected JIRA tickets information to Elastic Search Index
    Parameters
    ----------
    None.
    Returns
    -------
    None.

    """
    try:

        conn_es = kibana_connect_es(project_key)
        if project_key == "SOC":
            index_doc_mapper = [
                {"_index": 'elastic_index_name',
                 "_id": doc['Issue_Key'],
                 "_source": doc
                 }
                for doc in final_dump_into_elastic]
            # status = bulk_push_to_elastic(
            #     index_doc_mapper, conn_es)

        elif project_key == "SOC24027D":
            filtered_issues = filter_plant_based_issues(
                final_dump_into_elastic)
            for key, value in filtered_issues.items():
                if not value:
                    continue
                if key == "ptt_gsp4_issues":
                    index_doc_mapper = [
                        {"_index": 'elastic_index_name',
                         "_id": doc['Issue_Key'],
                         "_source": doc
                         }
                        for doc in value]
                    status = bulk_push_to_elastic(
                        index_doc_mapper, conn_es)
                elif key == "ptt_gsp7_issues":
                    if not value:
                        continue
                    index_doc_mapper = [
                        {"_index": 'elastic_index_name',
                         "_id": doc['Issue_Key'],
                         "_source": doc
                         }
                        for doc in value]
                    # status = bulk_push_to_elastic(
                    #     index_doc_mapper, conn_es)
                elif key == "ptt_rayong_issues":
                    if not value:
                        continue
                    index_doc_mapper = [
                        {"_index": 'elastic_index_name',
                         "_id": doc['Issue_Key'],
                         "_source": doc
                         }
                        for doc in value]
                    # status = bulk_push_to_elastic(index_doc_mapper, conn_es)
                else:
                    if not value:
                        continue
                    index_doc_mapper = [
                        {"_index": 'elastic_index_name',
                         "_id": doc['Issue_Key'],
                         "_source": doc
                         }
                        for doc in value]
        if index_doc_mapper:
            status = bulk_push_to_elastic(index_doc_mapper, conn_es)
            
            print(status)
            return status

    except Exception as e:
        logger.error("Got error in export_to_elastic function with error:%s.",
                     e)


def dict_list_to_markdown_table(data_list, columns=None):
    """
    Convert a list of dictionaries into a Markdown table.
    Handles varying keys by using the union of all keys.
    Missing values are replaced with blanks.
    """
    if not data_list:
        return "No data available."

    # Collect all unique keys across all dictionaries
    all_keys = set()
    for item in data_list:
        all_keys.update(item.keys())
    columns = sorted(all_keys)  # Sort for consistency

    # Header row
    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join(["---"] * len(columns)) + " |"

    # Data rows
    rows = []
    for item in data_list:
        row = "| " + " | ".join(str(item.get(col, ""))
                                for col in columns) + " |"
        rows.append(row)

    # Combine into Markdown table
    markdown_table = "\n".join([header, separator] + rows)
    return markdown_table


def print_final_automation_stats(ai_agent_l1_acknowledgement_Task):
    """
    This Function tries to print the final automation stats.
    Parameters
    ----------
    None.
    Returns
    -------
    None.

    """
    try:
        # Step 1: Separate issue keys and metadata safely
        issue_keys = [v for item in ai_agent_l1_acknowledgement_Task if isinstance(
            item, (list, tuple)) and len(item) == 2 and item[0] == 'Issue_Key' for v in [item[1]]]
        metadata = {k: v for item in ai_agent_l1_acknowledgement_Task if isinstance(
            item, (list, tuple)) and len(item) == 2 and item[0] != 'Issue_Key' for k, v in [item]}

        # Step 2: Group metadata under each issue key
        grouped_data = {key: {k: v for k, v in metadata.items()}
                        for key in issue_keys}
        pdb.set_trace()
        print(grouped_data)

        return grouped_data
    except Exception as e:
        logger.error("Got error in print_final_automation_stats function with error:%s.",
                     e)


def main():
    """
    This Function will trigger end to end automation process. 
    Parameters
    ----------
    None.
    Returns
    -------
    None.
    """
    try:
        process_start = datetime.datetime.now()
        # projects = ['SOC', 'SOC24027D','SOC2510D']
        projects = ['SOC24027D']

        ai_agent_l1_acknowledgement_Task = []
        for project_key in projects:
            logger.info(
                "Starting AI processing Agent L1 Task for Project: %s with lookback time of %d minutes", project_key, lookback_minutes)
            print("Starting AI processing Agent L1 Task for Project: {} and lookback time of {} minutes".format(
                project_key, lookback_minutes))
            # Triggering Function - Create Elastic Connection Object
            es_all_issues = get_jira_tickets_from_elastic(project_key)
            if es_all_issues:
                ai_agent_l1_acknowledgement_Task.extend(ai_l1_processing_agent_operations(
                    es_all_issues, project_key))

                # # all_items = [(key, value) for d in ai_agent_l1_acknowledgement_Task for key, value in d.items()]
                # all_items = "\n".join([
                #     f"project_key : {d['project_key']} -- issue_key : {d['issue_key']} -- acknowledgement_status : {d['acknowledgement_Status']}"
                #     for d in ai_agent_l1_acknowledgement_Task
                # ])

                # # all_items = [
                # #     (key, value)
                # #     for d in ai_agent_l1_acknowledgement_Task if isinstance(d, dict)
                # #     for key, value in d.items()
                # # ]
                # automation_stats = print_final_automation_stats(
                #     ai_agent_l1_acknowledgement_Task)
                markdown_output = dict_list_to_markdown_table(
                    ai_agent_l1_acknowledgement_Task)
                logger.info(
                    "\nCompleted AI processing Agent L1 Acknowledgement Task for Project: %s", project_key)
                logger.info("Agentic L1 Processed Ticket ID's: %s",
                            str(markdown_output))
                print("\nCompleted AI processing Agent L1 Acknowledgement Task for Project: ",
                      project_key)
                print(
                    "\nAgentic L1 Processed Ticket ID's: ", str(markdown_output))

            else:
                logger.info(
                    "No JIRA tickets found for project: %s within %d minutes", project_key, lookback_minutes)
                print("No JIRA tickets found for project: {} within lookback {}".format(
                    project_key, lookback_minutes))
            if ai_agent_l1_acknowledgement_Task:

                logger.info("Below tickets and its details are updating into Elastic Processing Index. \n\n %s ",
                            ai_agent_l1_acknowledgement_Task)
                status = export_to_elastic(
                    ai_agent_l1_acknowledgement_Task, project_key)
                if status:  # == "success":
                    logger.info("AI L1 Processing Agent has successfully processed and exported %s tickets into Elastic Search Index for project %s.", len(
                        ai_agent_l1_acknowledgement_Task), project_key)
                else:
                    logger.error(
                        "AI L1 Processing Agent failed to export processed tickets into Elastic Search Index for project %s.", project_key)
            else:
                logger.info(
                    "No tickets processed by AI L1 Processing Agent for project: %s", project_key)

        process_end = datetime.datetime.now()  # .strftime("%Y-%m-%d %H:%M:%S")
        process_total_time = process_end - process_start
        print("Total Time Consumed for the Automation : {}".format(
            str(process_total_time)))

    except Exception as e:
        print("Got error in main function with error:", e)
        logger.error("Got error in main function with error:%s.",
                     e,
                     exc_info=False)


if __name__ == "__main__":
    
    lookback_minutes = 10
    agent_services = ["AI_Ticket_Assignment", "AI_Ticket_Status_Update", "AI_Ticket_Organization_Update",
                      "AI_Usecase_Knowledge_Comparison", "AI_Generate_Recommandations",
                      "AI_Ticket_Resolution", "AI_Ticket_Escalation"]
    at_timestamp = datetime.datetime.strptime(str(datetime.datetime.now(
        pytz.timezone('Asia/Bangkok'))).split(".")[0], "%Y-%m-%d %H:%M:%S")
    main()

    """
    Note: below checks has to be done before prod move
    1. Check the JIRA account id's for Automation account.
    2. Project Key has to be mapped according to environment (dev, prod)
    3. Check the JIRA API token for Automation account and its expiry 
    4. customfield for organization id. "customfield_10002 for Organization in PTT dev "
    5. verify= False in requests API calls has to be trun it to True.
    6. get all the L2 and L3 members account id's and map it in account_ids dict.
    7. Check the status codes mapping with JIRA instance.
    8. Finalize the delay timer for ticket resolved to closure ex: 12hr/24hrs.

    """
