from time import sleep
from helper.project_info import *
from helper.project_secrets import *

from openai import OpenAI
client = OpenAI(api_key=OPENAI_API_KEY)


def llm_endpoint_call(prompt): # In this OpenAI example, we are not using max_tokens
    # Send the request to the API
    sleep(2.273484748383) # Sleep time that appears to be random/natural
    response = client.chat.completions.create(
        model=LLM_MODEL,
        temperature=LLM_TEMPERATURE,
        messages=[
            {"role": "system", "content": SYSTEM_MESSAGE},
            {"role": "user", "content": prompt},
        ]
    )
    return response.choices[0].message.content


def llm_chat_endpoint(pentest_data, chat_content):
    # Send the request to the API
    sleep(2.273484748383)  # Sleep time that appears to be random/natural
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        temperature=LLM_TEMPERATURE,
        messages=[
            {"role": "system", "content": "You are a helpful pentesting assistant named Atom. Provided with data about a paticular authorized black box pentest, you answer questions as you are asked them, matching the precived knowledge level from the latest question, to add the most value to the user."},
            {"role": "assistant", "content": "Hello human, I am Atom. Please provide your pentest data in json format so I can best assist you."},
            {"role": "user", "content": str(pentest_data)},
            *[{"role": msg["role"], "content": msg["content"]} for msg in chat_content],
        ]
    )
    return response.choices[0].message.content