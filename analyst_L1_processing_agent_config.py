"""

Below are the mapping of transition ID and resolution with transition labels. Thank You 
 
OPEN
Transition=1 -- open
Transition=31 -- Investigate (open to work in progress)
Transition=211 ---resolved (open to resolved)
 
Work in progress
Transition=3 --- Internal escalation (Work in progress to work in progress by L2)
Transition=311 ---- Pending (Work in progress to pending)
Transition=271 ---- Waiting For Customer (work in progress to Waiting For Customer)
Transition=331 ---- resolved (Work in progress to resolved)
Transition=5 ---- Back to work in progress (work in progress by L3 to work in progress)
Transition=7 --- Back to work in progress (work in progress by L2 to work in progress)
Transition=281 --- work in progress (Waiting for customer to work in progress)
Transition=321 -- work in progress (pending to work in progress)
Transition=121 ---- Back to work in progress (Resolved to work in progress)
 
Work in progress by L2
Transition=7 ---- Back to work in progress (work in progress by L2 to work in progress)
Transition=4 ---- Internal escalation (Work in progress by L2 to Work in progress by L3)
Transition=8 --- resolved (Work in progress by L2 to resolved)
Transition=6 ---- internal de-escalation (work in progress by L3 to work in progress to L2)
Transition=3 --- Internal escalation (Work in progress to work in progress by L2)
 
Work in progress by L3
Transition=5 ----- Back to work in progress (work in progress by L3 to work in progress)
Transition=6 ---- internal de-escalation (work in progress by L3 to work in progress to L2)
Transition=9 ---- resolved (Work in progress by L3 to resolved)
Transition=4 ---- Internal escalation (Work in progress by L2 to Work in progress by L3)
 
Pending 
Transition=321 -- work in progress (pending to work in progress)
Transition=10 --- pending (Waiting for customer to pending)
Transition=311 --- pending (Work in progress to pending)
 
Waiting for Customer
Transition=10 ---- pending (Waiting for customer to pending)
Transition=281 --- work in progress (Waiting for customer to work in progress)
Transition=2 --- Resolved (waiting for customer to resolved)
Transition=271 ---- Waiting For Customer (work in progress to Waiting For Customer)
 
Resolved
Transition=121 ---- Back to work in progress (Resolved to work in progress)
Transition=91 --- close (resolved to close)
Transition=211 ---- -resolved (open to resolved)
Transition=2 ---- Resolved (waiting for customer to resolved)
Transition=8 --- resolved (Work in progress by L2 to resolved)
Transition=9 ---- resolved (Work in progress by L3 to resolved)
Transition=331  ---- resolved (Work in progress to resolved)
 
close 
Transition=91 --- close (resolved to close)
                                
"""

ticket_status_codes = {"Open": 1, "Open_To_Work_In_Progress": 31,

                       "Work_In_Progress_To_Waiting_For_Customer": 271,
                       "Work_In_Progress_To_Work_In_Progress_By_L2": 3,
                       "Work_In_Progress_By_L2_To_Work_In_Progress": 000,
                       "Work_In_Progress_By_L3_To_Work_In_Progress": 000,
                       "Work_In_Progress_To_Resolved": 331,

                       "Waiting_For_Customer_To_Resolved": 2,
                       "Waiting_For_Customer_To_Work_In_Progress": 281,
                       "Waiting_For_Customer_To_Work_In_Progress_By_L2": 000,

                       "Work_In_Progress_By_L3": 10181,
                       "Pending": 10005, "Resolved": 311, "Resolved_To_Closed": 91,
                       "Jira_Ticket_Next_Steps": None}


account_ids = {
    "ITOTSOC-25-010-AutoAlerts": "Your_Acoount_ID",
    "ITOTSOC-24-027-AutoAlerts": "Your_Acoount_ID",
    "Koushik": "Koushik_Account_ID"
}

Jira_Account_ID = {'Jira_Admin': {'Jira_API_Name': 'Jira_API_Key'},
                   
                   }

ticket_Org_codes = {"SOC24027D": [
    {'id': '47', 'name': 'YIL'}], "SOC24027": [{'id': '48', 'name': 'YTH'}]}
