"""
Created on Thu Sep 29 11:05 2025

AUTHOR      : Sai Koushik Parachi
EMAIL       : Parachi.SaiKoushik@yokogawa.com
VERSION     : v1
FileName    : analyst_L1_queueing_agent_main.py
Objective   : This python file helps to pull the latest(created/updated) Jira ticket details and store in elastic DB.
              This task will be performed to execute with every 2 minutes of duration.

Parameters  :
    INPUT   : Jira and Elastic account details, 
    OUTPUT  : Latest Jira ticket details stored in Elastic DB.

Referance Doc: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-comments/#api-rest-api-3-issue-issueidorkey-comment-post
"""
from pytz import timezone
from analyst_L1_queueing_agent_imports import *
from analyst_L1_queueing_agent_config import *


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
        elif request_type == 'assign_jira_tickets':
            jira_connection_details |= {
                "jira_url": "https://jira_url/rest/api/3/issue/assignee_id/assignee/"}

        return jira_connection_details
    except Exception as e:
        logger.error("Got error in jira_request_object function with error:%s.",
                     e)


def get_jira_tickets(project_key):
    """
    This Function tries to Fetch JIRA tickets information from JIRA DB via REST API.
    Parameters
    ----------
    None.
    Returns
    -------
    all_issues : List Object.

    """
    try:
        start_at = 0
        all_issues = []
        MAX_RESULTS_PER_PAGE = 100
        jira_connection_details = jira_connection_object(
            'get_jira_tickets', project_key)

        def get_weeks_count():
            """Get the count of weeks for which JIRA issues are available.

            Returns:
                dict: A dictionary with week numbers as keys and issue counts as values.
            """
            try:
                all_weeks_response = []
                all_issues = []
                next_page_token = None
                is_last = False
                # # Calculate the date 1 week months ago
                week_ago = datetime.datetime.now() - timedelta(days=1)
                week_ago_str = week_ago.strftime(
                    '%Y-%m-%d')  # +"T00:00:00.000"
                
                # from datetime import  timezone
                # Calculate time 10 minutes ago in UTC
                ten_minutes_ago = (datetime.datetime.now(datetime.timezone.utc) - timedelta(minutes=1000)).strftime("%Y-%m-%d %H:%M")


                # # # JQL query to get incidents from the last 1 week
                # jql_query = f'project = "{str(project_key)}" AND (created >= "{week_ago_str}" OR updated >= "{week_ago_str}")'
                # # JQL query to get incidents from the last lookback_minutes time
                # jql_query = f'project = "{project_key}" AND (created >= -{ten_minutes_ago}m OR updated >= -{ten_minutes_ago}m)'
                
                
                # JQL query with parentheses
                jql_query = f'project = "{project_key}" AND (created >= -{lookback_minutes}m OR updated >= -{lookback_minutes}m)'
                # jql_query = f'project = "SOC24027D" AND (updated >= "{ten_minutes_ago}" OR created >= "{ten_minutes_ago}")'

                while not is_last:

                    payload = {
                        'jql': jql_query,
                        "fields": [
                            "*all"
                        ],
                        'maxResults': 2000,
                    }
                    if next_page_token:
                        payload["nextPageToken"] = next_page_token

                    weeks_response = requests.post(jira_connection_details['jira_url'], headers=jira_connection_details['headers'],
                                                   data=json.dumps(payload), auth=(jira_connection_details['username'], jira_connection_details['api_token']), verify=False)

                    data = weeks_response.json()

                    issues = data.get("issues", [])
                    all_weeks_response.extend(issues)
                    next_page_token = data.get("nextPageToken")
                    is_last = data.get("isLast", True)

                    if not next_page_token:
                        break
                # paginations = {}
                if weeks_response.json()['issues']:

                    for issue in all_weeks_response:
                        # issue_id = issue['key']
                        all_issues.append(issue)
                        len_all_issues = len(all_issues)
                else:
                    all_issues = None
                    len_all_issues = 0
                print("Fetched Len of all_issues:"+str(len_all_issues))
                # print("Time to End Fetching JIRA tickets detail: " +
                #         datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                return all_issues
            except Exception as e:
                logger.error("Got error in get_weeks_count function with error:%s.",
                             e)

        all_issues = get_weeks_count()
        return all_issues

    except Exception as e:
        logger.error("Got error in get_jira_tickets function with error:%s.",
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
        jira_connection_details = jira_connection_object(
            'create_jira_tickets', project_key)
        # jsdPublic = False

        # If jsdPublic is True, then the comment will be visible to customers in the portal.
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
            response = requests.post(url, json=payload, headers=headers, verify=False,)

        if response.status_code == 201:
            logger.info("Comment added successfully to %s", issue['key'])
            # print(f"Comment added successfully
            print(f"\nComment added successfully to {issue['key']}")
        else:
            logger.error("Failed to add comment: %s - %s",
                         response.status_code, response.text)
            print(
                f"Failed to add comment: {response.status_code} - {response.text}")

    except Exception as e:
        logger.error("Got error in post_latest_comments function with error:%s.",
                     e)


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
                            "Acknowledged_by": "AI Queueing Agent L1"}
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


def ai_l1_queueing_agent_operations(all_issues, project_key):
    """
    This Function tries to process JIRA tickets information and push them into Elastic Search.
    Parameters
    ----------
    all_issues : List Object.
        DESCRIPTION: Holds the JIRA tickets information.
    project_key : String Object.
        DESCRIPTION: Holds the JIRA project key.

    Returns
    -------
    None.
    """
    try:
        if not all_issues:
            logger.info(
                "No JIRA tickets found for project: %s by AI Queueing Agent L1", project_key)
            return
        ai_agent_l1_tickets = []
        
        for issue in all_issues:
            print("\n\nAI Agent L1 Acknowledging JIRA ticket: ", issue['key'])
            logger.info(
                "AI Agent L1 Acknowledging JIRA ticket: %s", issue['key'])
            # if issue['key'] != 'SOC24027D-263006':
            #     pass #SOC24027D-263778
            # else:
            ai_agent_l1_text_dict = {}
            recent_comments = []
            recent_comments = get_issue_latest_comments(
                recent_comments, issue, project_key)

            # for rec_comm in recent_comments:
            #     print("\nRecent Comments: ", rec_comm)
            # if recent_comments[-1]['proceed_for_acknowledgement'] == True:
            # if rec_comm['proceed_for_acknowledgement'] == True:
            for latest_comment in recent_comments:
                ai_agent_l1_text_dict.update(latest_comment)
                if latest_comment['proceed_for_acknowledgement']:
                    complete_descriptuion = find_all_text_values(
                        latest_comment['comment'])
                    if "AI-powered L1 Agent's Transcript".lower() in complete_descriptuion.lower():
                        ai_agent_l1_text_dict |= {
                            "project_key": project_key
                        }
                        ai_agent_l1_text_dict |= {
                            "issue_key": issue['key']
                        }
                        ai_agent_l1_text_dict |= {
                            "acknowledgement_Status": "Not_Required"
                        }
                        ai_agent_l1_text_dict |= {
                            "acknowledgement_Status": "Not_Required"
                        }
                        ai_agent_l1_text_dict.update(latest_comment)
                        ai_agent_l1_tickets.append(ai_agent_l1_text_dict)
                        continue
                    if complete_descriptuion:
                        ai_agent_l1_text = f"Hello, This is an automated acknowledgement from AI Agent L1. We have received ticket {issue['key']}. Our AI Agent L1 will review the details and get back to you shortly.\n\n\n Disclaimer: It's an AI-powered L1 Agent's Transcript. Please do not reply to this comment."
                        post_latest_comments(
                            issue, project_key, ai_agent_l1_text, True)#latest_comment['jsdPublic'])

                        print("\n\nAI Agent L1 Acknowledged JIRA ticket: ",
                            issue['key'])
                        logger.info(
                            "AI Agent L1 Acknowledged JIRA ticket: %s", issue['key'])
                        ai_agent_l1_text_dict |= {
                            "project_key": project_key
                        }
                        ai_agent_l1_text_dict |= {
                            "issue_key": issue['key']
                        }
                        ai_agent_l1_text_dict |= {
                            "acknowledgement_Status": "Completed"
                        }
                        ai_agent_l1_tickets.append(ai_agent_l1_text_dict)

        # print(ai_agent_l1_tickets)
        return ai_agent_l1_tickets
    except Exception as e:
        logger.error("Got error in ai_l1_queueing_agent_operations function with error:%s.",
                     e)


def extract_req_fields(all_issues, project_key):
    """
    This Function tries to Extract required fields collected JIRA tickets information.
    Parameters
    ----------
    all_issues : List Object.
    Returns
    -------
    processed_data : List of Dictionaries.

    """
    try:
        if project_key == "SOC":
            kibana_jira_field_mapper = kibana_jira_field_mappings['irpc_fields_mapping']
        elif project_key == "SOC24027D":
            kibana_jira_field_mapper = kibana_jira_field_mappings['ptt_all_plants_fields_mapping']
        processed_data = []
        for issue in all_issues:
            issue_dict = {}
            issue_dict |= {
                '@timestamp': datetime.datetime.now(datetime.timezone.utc)}

            for issue_dict_pair in kibana_jira_field_mapper:
                try:
                    try:
                        issue_dict_value = eval(
                            kibana_jira_field_mapper[issue_dict_pair])
                    except Exception as e:
                        issue_dict_value = "Not Available"
                    issue_dict |= {issue_dict_pair: issue_dict_value}

                except Exception as e:
                    logger.error(
                        "Got error in extract_req_fields function with error:%s.", e)
                    pass
            issue_dict |= {
                # + "-" + issue_dict['Issue_Status']}  # issue_key_status
                'Issue_Key': issue_dict['Issue_Key']}
            processed_data.append(issue_dict)
            # print(issue_dict['Issue_Key'], "==", issue_dict['Issue_Status'])
        return processed_data  # [processed_data[1]]
    except Exception as e:
        logger.error("Got error in extract_req_fields function with error:%s.",
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

    except Exception as e:
        logger.error("Got error in export_to_elastic function with error:%s.",
                     e)


def final_dump_into_elastic(ai_agent_l1_acknowledgement_Task, dump_into_elastic):
    """_summary_

    Args:
        ai_agent_l1_acknowledgement_Task (_type_): required fields from ai_agent_l1_acknowledgement_Task
        dump_into_elastic (_type_): required fields from issues
    Returns:
        final_dump (_type_): final dump of both ai_agent_l1_acknowledgement_Task and dump_into_elastic joined on 'issue_key' field
    """
    try:

        final_dump_to_elastic = []
        for a in ai_agent_l1_acknowledgement_Task:
            filtered_dict = {}
            for b in dump_into_elastic:
                if a["issue_key"] == b["Issue_Key"]:
                    merged = {**a, **b}
                    keys_to_remove = {"comment", "proceed_for_acknowledgement", "jsdPublic", 'issue_key',
                                      'project_key', 'updated_timestamp'}

                    filtered_dict = {
                        k: v for k, v in merged.items() if k not in keys_to_remove}
                    final_dump_to_elastic.append(filtered_dict)

       
        return final_dump_to_elastic

    except Exception as e:
        logger.error("Got error in final_dump_into_elastic function with error:%s.",
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
        projects = ['SOC24027D'] #['ODC-24-ED--027-DEV']

        ai_agent_l1_acknowledgement_Task = []
        for project_key in projects:
            logger.info(
                "Starting AI Queueing Agent L1 Acknowledgement Task for Project: %s with lookback time of %d minutes", project_key, lookback_minutes)
            print("Starting AI Queueing Agent L1 Acknowledgement Task for Project: {} and lookback time of {} minutes".format(
                project_key, lookback_minutes))
            # Triggering Function - Create Elastic Connection Object
            all_issues = get_jira_tickets(project_key)
            if all_issues:
                ai_agent_l1_acknowledgement_Task.extend(ai_l1_queueing_agent_operations(
                    all_issues, project_key))
                dump_into_elastic = extract_req_fields(all_issues, project_key)
                final_dump_to_elastic = final_dump_into_elastic(
                    ai_agent_l1_acknowledgement_Task, dump_into_elastic)
                if final_dump_to_elastic:
                    export_to_elastic(final_dump_to_elastic, project_key)

                # all_items = [(key, value) for d in ai_agent_l1_acknowledgement_Task for key, value in d.items()]
                all_items = "\n".join([
                    f"project_key : {d['project_key']} -- issue_key : {d['issue_key']} -- acknowledgement_status : {d['acknowledgement_Status']}"
                    for d in ai_agent_l1_acknowledgement_Task
                ])

                # all_items = [
                #     (key, value)
                #     for d in ai_agent_l1_acknowledgement_Task if isinstance(d, dict)
                #     for key, value in d.items()
                # ]

                logger.info(
                    "Completed AI Queueing Agent L1 Acknowledgement Task for Project: %s", project_key)
                logger.info("Language Translated Ticket ID's: %s", all_items)
                print("Completed AI Queueing Agent L1 Acknowledgement Task for Project: ",
                      project_key)
                print("\nAI Queueing Agent L1 Acknowledged for Ticket ID's: ", all_items)

            else:
                logger.info(
                    "No JIRA tickets found for project: %s within %d minutes", project_key, lookback_minutes)
                print("No JIRA tickets found for project: {} within lookback {}".format(
                    project_key, lookback_minutes))

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
    automation_account_id = ["Account_Key","Account_Key",
                             ]
    lookback_minutes = 2
    at_timestamp = datetime.datetime.strptime(str(datetime.datetime.now(
        pytz.timezone('Asia/Bangkok'))).split(".")[0], "%Y-%m-%d %H:%M:%S")
    main()
