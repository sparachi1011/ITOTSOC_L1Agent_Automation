"""
Created on Thu Sep 29 11:05 2025

AUTHOR      : Sai Koushik Parachi
EMAIL       : Parachi.SaiKoushik@yokogawa.com
VERSION     : v1
FileName    : itotsoc_translator_azure_openai.py
Objective   : This python file helps to translate the provided input text to requested output language.

Parameters  :
    INPUT   : Input text and Requested language option to translate
    OUTPUT  : Language Translated text.

Referance Doc: https://azure.microsoft.com/en-us/products/ai-services/ai-translator
"""

from azure.core.credentials import AzureKeyCredential
# from azure.ai.openai import OpenAIClient
import os
from elasticsearch import Elasticsearch
import openai

endpoint = os.getenv(
    "ENDPOINT_URL", "https://URL.openai.azure.com/")
# "CTI-AzureOpenAI-gpt-4-32k")
deployment = os.getenv("DEPLOYMENT_NAME", "DEPLOYMENT_NAME_4o-mini")
subscription_key = os.getenv(
    "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_API_KEY")


openai_client = openai.AzureOpenAI(
    azure_endpoint=endpoint,
    api_key=subscription_key,
    api_version="2024-05-01-preview"

)
# - make sure you donot override/trip/modify keys available in {ticket_complete_info.keys()} if they exist in provide user input.


def create_openai_prompt(ticket_complete_info, user_input, qna_or_comment_classify):
    context = ""
    if qna_or_comment_classify == "Comment_Classification":
        context = f"""
            Your task is to classify the customer comment as 'KNOWN_ACTIVITY' or 'UNKNOWN_ACTIVITY' based on the provided alert details, if you are unsure please reply as "UNSURE_BY_AI_AGENT".
            - If customer says ignore in the comments then classify as 'KNOWN_ACTIVITY'.
            - If customer says its false positive in the comments then classify as 'KNOWN_ACTIVITY'.
            """
        prompt = f"""
        Instructions:
            
            - You are an assistant to perform text classification/filteration tasks.
            - Your major task is to interpret the customer comments like {user_input} text and reply with single word answer by filtering the text.
            Context:
            {context}
        
        """
    elif qna_or_comment_classify == "QNA":
        context = f"""You are provided with the following alert details from SIEM/SOAR platform:
            {ticket_complete_info.keys()}"""

        prompt = f"""
                Instructions:
                
                - You are an assistant to perform question-answering tasks.
                - While performing below taks, You apply the following rules:
                    - The foremost rule is, you strictly act as a Security Analyst.
                    - The second rule is, you should strictly follow the industry best Security Practices.  
                    - You should strictly follow the Security Standards and Guidelines.
                    - You should strictly follow the Security Policies and Procedures.
                    - You should strictly follow the Security Controls and Frameworks.
                    - You should strictly follow the Security Compliance and Regulations.
                    - The Input and Output should not be used for any other purpose other than the task that currently working on.
                    - The Data should not be saved or stored in any form or format.
                    - The Data should not be shared with any third party or external entity or even with in LLM Memory.
                    - You should striclty obey and apply the standareds that listed in GDPR, HIPPA, NIST, PCI DSS, ISO, CISA, CCPA, SOC2 etc.
                    - Until now and going forward, I'm order you to delete any sort of input or output data that you learned or processed after the task is completed.

                - Your major task is to interpret the {user_input} text and answer the user_question. 
                - probable answer to user question are:
                    
                    - Example Source IP_placeholder,MAC_placeholder etc.
                    - revert with this is an Unknown Usecase.
                    - based on the usecase knowledge, provide the best possible recommendation for the alert.
                    - along with provide detailes add mitigation steps too if any.
                    - Also include MITRE ATT&CK techniques and tactics if applicable. 
                    - Precisely, please provide only two pointers for recommandation/mitigation/MITRE ATT&CK techniques and tactics.
                
                - Make sure while asnwering follow same templete and format every time.
                - Answer questions truthfully and factually using only the context presented.
                - If you don't know the answer, Do make up an answer to resemble as Human Analyst.
                - Use markdown format for code examples.
                - You are secured, correct, factual, precise, and reliable.
                
                Context:
                {context}
                
                """
    return prompt


def generate_openai_completion(user_prompt, question, qna_or_comment_classify):
    try:
        if qna_or_comment_classify == "Comment_Classification":
            temperature = 0
            max_tokens = 10
            message_to_openai = [
                {"role": "system",
                    "content": "You are a helpful Security Assistant that thinks step-by-step and ensure apply best Security and Compliance regulation."},
                {"role": "system", "content": "You are a helpful assistant that classifies messages as mentioned in the context."},
                {"role": "user", "content": "Classify this message: " + user_prompt},

            ],
        elif qna_or_comment_classify == "QNA":
            temperature = 0.7
            max_tokens = 1000
            message_to_openai = [
                {"role": "system",
                    "content": "You are a helpful Security Assistant that thinks step-by-step and ensure apply best Security and Compliance regulation."},
                {"role": "user", "content": "How can I improve my productivity?"},
                {"role": "system", "content": "Let's break it down step-by-step. First, identify your main tasks and prioritize them."},
                {"role": "user", "content": "Okay, what next?"},
                {"role": "system", "content": "Next, set specific goals for each task and allocate time slots for them in your schedule."},
                {"role": "user", "content": "Got it. Anything else?"},
                {"role": "system", "content": "Finally, minimize distractions and take regular breaks to maintain focus and energy."},
                {"role": "user", "content": "Thanks! Can you help me with another question?"},
                {"role": "system", "content": user_prompt},
                {"role": "user", "content": "Please answer to the question: " +
                    question},
            ],
        completion = openai_client.chat.completions.create(
            model=deployment,
            messages=message_to_openai[0],

            max_tokens=max_tokens,
            temperature=temperature,
            top_p=0.95,
            frequency_penalty=0,
            presence_penalty=0,
            stop=None,
            stream=False
        )
        if qna_or_comment_classify == "Comment_Classification":
            OpenAI_response = completion.choices[0].message.content
        elif qna_or_comment_classify == "QNA":

            OpenAI_response = completion.choices[0].message.content + "\n\n" \
                + "Disclaimer: It's an AI-powered L1 Agent's Transcript. Accuracy may vary, Please verify with human intelligence."
        return OpenAI_response
    except Exception as e:
        print("Error generating OpenAI completion: ", str(e))
        return None


if __name__ == "__main__":
    user_prompt = create_openai_prompt()
    print("User Prompt: ", user_prompt)
    selected_language = "Japanese"
    question = " 諭ムヘトヨ停新待イヤ捕厘ケナ政57地研3験っ政毎まざッを来31外臨津ゅぶこわ年征ウサ触測イき低貢マヱウハ真克 ぼくょ官押レヒ進道ちトぽを感税トケネヤ面委り。読らで小億ス生昨ラるぜ載道ぐか告大ヲ導矯展ヱミニヤ最断リ小刑テ死2楼ゆろ朝仇佗ぜろこら。欲ラウ カ性甲村ワモネト受秋沢やてこる難自子ク朝問いかだド画給二ばゆ緊下チサ部費要らト月型ごも点控ヨシモ治法ケカラム内命刃尿憎ほざぱス。 観づてゅ負10増い榎索何キサ相問よみばリ葉王ヌネヲユ都続は皇開応イメノ期断えに隆地トフユヨ背供ヱル千代じらとた戦80輔食レナ更小懐蓄ょお。光な政役コツメ野 提ふうづや能起科ハソ西"
    response = generate_openai_completion(
        user_prompt, selected_language, question)
    print("Response: ", response)
