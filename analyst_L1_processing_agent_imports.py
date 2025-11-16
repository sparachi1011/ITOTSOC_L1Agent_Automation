"""
Created on Thu Sep 29 11:05 2024

AUTHOR      : Sai Koushik Parachi
EMAIL       : Parachi.SaiKoushik@yokogawa.com
VERSION     : v1
FileName    : jira_open_ai_translator_integration_imports.py
Objective   : This python file try to load and intialize necessary python libraries and share across automation scripts.

Parameters  :
    INPUT   : None.
    OUPUT   : Python Library Objects.

"""
# pip install langdetect

from langdetect import detect
from jira import JIRA
from flask import Flask, request, render_template
import datetime
import pytz
from datetime import timedelta
from elasticsearch import Elasticsearch, helpers
from requests.auth import HTTPBasicAuth
import requests
from requests.auth import HTTPBasicAuth
import json
import os,re
import sys
import pdb
import base64
import pandas as pd
import logging
import subprocess
import warnings
warnings.filterwarnings("ignore", category=Warning)


alert_details_df = pd.DataFrame()
# timestamp = (datetime.datetime.utcnow()).strftime('%Y-%m-%d %H:%M:%S')

# datetime.timezone.utc)  # .strftime('%Y-%m-%d %H:%M:%S')

if os.name == 'nt':
    jira_open_ai_translator_module_path = os.getcwd() + "/"
if os.name == 'posix':
    # jira_open_ai_translator_module_path = "/home/ec2-user/YSOC_jira_open_ai_translator_Module/"
    jira_open_ai_translator_module_path = "/var/lib/jenkins/gitlab_project_execution_logs/"

print("The Project Working Directory: "+jira_open_ai_translator_module_path)


def check_file_or_create(sub_path, check_type):
    """Check if a file exists or create it if it doesn't.

    Args:
        sub_path (str): The subdirectory path where the file is located.
        check_type (str): The type of file to check (e.g., ".log" or ".json").

    Returns:
        str: The path to the log or JSON file.
    """
    try:
        if check_type == ".log":
            file_path = jira_open_ai_translator_module_path + sub_path + \
                str(datetime.datetime.now().strftime("%Y_%m_%d")) + '.log'
        elif check_type == ".json":
            file_path = jira_open_ai_translator_module_path + sub_path + \
                str(datetime.datetime.now().strftime("%Y_%m_%d_%H_%M")) + '.json'
        if os.path.exists(file_path.rsplit("/", 1)[0]):
            if os.path.exists(file_path):
                file_name = file_path
            else:
                log_file = open(file_path, 'a')
                log_file.close()
                file_name = file_path
        else:
            try:
                # # print("\n&&&&&&MakeDirectoryFromImports.py", ysoc_module_path)
                os.mkdir(file_path.rsplit("/", 1)[0])  # , mode=0o777)
                # os.mkdir('./execution_logs')#, mode=0o777)
                log_file = open(file_path, 'a')
                log_file.close()
                file_name = file_path
                # # print("\n&&&&&&AfterMakeDirectoryFromImports.py", ysoc_module_path)
            except Exception as e:
                print("Error while creating log file from imports.py\n", e)

        return file_name
    except Exception as e:
        print("Got Error in generate_logger function as:\n", e)


def generate_logger():
    """Generate a logger for the application.

    Returns:
        logging.Logger: The logger object.
    """
    try:
        sub_path = 'analyst_l1_processing_agent_module_logs/analyst_l1_processing_agent_module_logs_'
        file_name = check_file_or_create(sub_path, ".log")
        if file_name:
            try:
                log_process_activities(
                    'analyst_l1_processing_agent_module_logs', file_name)
                logger = logging.getLogger(
                    'analyst_l1_processing_agent_module_logs')
            except Exception as e:
                log_process_activities(
                    'analyst_l1_processing_agent_module_logs', file_name)
                logger = logging.getLogger(
                    'analyst_l1_processing_agent_module_logs')
        return logger, file_name
    except Exception as e:
        print("Got Error in generate_logger function as:\n", e)


def log_process_activities(logger_name, log_file):
    """
    This Function will create a logger object.

    Parameters
    ----------
    logger_name : String
        DESCRIPTION: name of the logger object.
    log_file : String
        DESCRIPTION: Path to log file.
    logger_level : String
        DESCRIPTION: Level of logging to be tracked.

    Returns
    -------
    Logger object.

    """
    try:
        level = logging.INFO
        logger = logging.getLogger(logger_name)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s')
        fileHandler = logging.FileHandler(log_file, mode='a')
        fileHandler.setFormatter(formatter)
        logger.setLevel(level)
        logger.addHandler(fileHandler)

        return logger
    except FileNotFoundError as error:
        logger.error(
            "FileNotFoundError at log_process_activities " + str(error))
    except Exception as error:
        logger.error("Error at log_process_activities " + str(error))


logger, log_file_path = generate_logger()
ysoc_secrets = {'ysoc_pcap_analysis_script': {
                "elastic_endpoint": "Elastic_URL",
                'elastic_creds': {'irpc_script_execution': 'Password', "ptt_script_execution": "Password", }}
                }
