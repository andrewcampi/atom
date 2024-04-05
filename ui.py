# PyWebIO imports
import pywebio
from pywebio import *
from pywebio.input import *
from pywebio.output import *
from pywebio.pin import *
from pywebio.session import *
from functools import partial
# Atom imports
from client import *
# General imports
from time import sleep
import os
import re
import requests
import json


app_name = "Atom."
port = 80
debug = True


MAX_MESSAGES_CNT = 35
chat_msgs = []  # The chat message history. The item is (name, message content)


def do_nothing():
    pass

def remove_footer():
    js_code = "document.querySelector('footer.footer').remove();"
    run_js(js_code)

@config(theme="dark")
def menu():
    session.set_env(title='Atom.', output_max_width='40%')
    remove_footer()
    clear()
    for x in range(4):
        put_text(" ")
    logo = open('images/hero.png', 'rb').read()
    put_image(logo, width="5000px")
    put_text(" ")
    put_row([None, put_button("View API Docs", onclick=lambda:view_docs()), None, put_button("Launch App", onclick=lambda:launch_app()), None], size='18% 25% 15% 25%')


def view_docs():
    session.set_env(title='Atom.', output_max_width='95%')
    clear()
    remove_footer()
    put_button("Menu", onclick=lambda:menu())
    put_text(" ")
    
    # Introduction
    put_markdown("# Atom Pentesting Assistant API Documentation")
    put_text("Atom is a versatile pentesting assistant designed to streamline the process of conducting penetration tests. Below is the detailed API documentation, including endpoints, request methods, expected inputs, and outputs.")
    
    # Documentation for each endpoint
    ## /start
    put_markdown("## `/start`")
    put_text("Initiates a new penetration test session.")
    put_table([
        ['Parameter', 'Required', 'Description'],
        ['pentest_name', 'Yes', 'Name of the penetration test.'],
        ['target_ip', 'Yes', 'Target IP address for the pentest.'],
    ])
    put_code('POST /start\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "target_ip": "192.168.1.1"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "command": "nmap 192.168.1.1 -sV -T4 -sC"\n}', language='json')
    put_text(" ")

    ## /end
    put_markdown("## `/end`")
    put_text("Terminates the pentest session and deletes session data.")
    put_code('POST /end\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "pentest_name": "test_session",\n    "target_ip": "192.168.1.1",\n    "nmap_output": "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",\n    "attack_surface": [\n        {\n            "port_number": 80,\n            "detected_service_version": "Apache/2.4.41",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        }\n    ],\n    "attack_paths": [\n        {\n            "path_name": "path1",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        }\n    ],\n    "extra_details": {\n        "os_name": "Linux"\n    }\n}', language='json')
    put_text(" ")
    
    # /get_all_current_info
    put_markdown("## `/get_all_current_info`")
    put_text("Retrieves all current information for a specific pentest session.")
    put_table([
        ['Parameter', 'Required', 'Description'],
        ['pentest_name', 'Yes', 'Name of the penetration test session.'],
    ])
    put_code('POST /get_all_current_info\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "pentest_name": "test_session",\n    "target_ip": "192.168.1.1",\n    "nmap_output": "Nmap scan report for ...",\n    "attack_surface": [\n        {\n            "port_number": 80,\n            "detected_service_version": "Apache/2.4.41",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        }\n    ],\n    "attack_paths": [\n        {\n            "path_name": "path1",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        }\n    ],\n    "extra_details": {\n        "os_name": "Linux"\n    }\n}', language='json')
    put_text(" ")
    
    # /provide/nmap_output
    put_markdown("## `/provide/nmap_output`")
    put_text("Updates the pentest session with the output from an Nmap scan.")
    put_table([
        ['Parameter', 'Required', 'Description'],
        ['pentest_name', 'Yes', 'Name of the pentest session.'],
        ['nmap_output', 'Yes', 'The output from the Nmap scan command.'],
    ])
    put_code('POST /provide/nmap_output\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "nmap_output": "Nmap scan report for ..."\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "status": "success"\n}', language='json')
    put_text(" ")
    
    # Example for a complex endpoint with HTML output
    put_markdown("## `/determine/attack_surface`")
    put_html("""
    <p>Determines the attack surface based on the provided Nmap scan output.</p>
    <table>
        <tr>
            <th>Parameter</th><th>Required</th><th>Description</th>
        </tr>
        <tr>
            <td>pentest_name</td><td>Yes</td><td>Name of the penetration test.</td>
        </tr>
        <tr>
            <td>nmap_output</td><td>Yes</td><td>Output from the Nmap scan command.</td>
        </tr>
    </table>
    """)
    put_code('POST /determine/attack_surface\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "nmap_output": "..."\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "attack_surface": [\n        {\n            "port_number": 80,\n            "detected_service_version": "Apache/2.4.41",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        },\n        {\n            "port_number": 22,\n            "detected_service_version": "OpenSSH 7.9p1",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        }\n    ]\n}', language='json')
    put_text(" ")

    # /determine/attack_paths
    put_markdown("## `/determine/attack_paths`")
    put_text("Identifies possible attack paths based on the current attack surface and session data.")
    put_table([
        ['Parameter', 'Required', 'Description'],
        ['pentest_name', 'Yes', 'Name of the penetration test.'],
    ])
    put_code('POST /determine/attack_paths\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "attack_paths": [\n        {\n            "path_name": "path1",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",\n            "service_name": "apache",\n            "service_version": "2.4.41"\n        },\n        {\n            "path_name": "path2",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",\n            "service_name": "ssh",\n            "service_version": "OpenSSH 7.9p1"\n        }\n    ]\n}', language='json')
    put_text(" ")

    # /determine/extra_details
    put_markdown("## `/determine/extra_details`")
    put_text("Gathers extra details that may be relevant to the pentest from the Nmap scan output.")
    put_code('POST /determine/extra_details\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "extra_details": {\n        "os_name": "Linux",\n        "hostname": "target_host"\n    }\n}', language='json')
    put_text(" ")

    # /determine/steps
    put_markdown("## `/determine/steps`")
    put_text("Determines the detailed steps for executing a selected attack path.")
    put_table([
        ['Parameter', 'Required', 'Description'],
        ['pentest_name', 'Yes', 'Name of the pentest session.'],
        ['attack_path_name', 'Yes', 'The selected attack path to detail.'],
    ])
    put_code('POST /determine/steps\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "attack_path_name": "example_path"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "steps": [\n        {\n            "step_name": "step1",\n            "tool_name": "tool1",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        },\n        {\n            "step_name": "step2",\n            "tool_name": "tool2",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        }\n    ]\n}', language='json')
    put_text(" ")

    # /determine/command
    put_markdown("## `/determine/command`")
    put_text("Generates the command for a specific step within an attack path.")
    put_table([
        ['Parameter', 'Required', 'Description'],
        ['pentest_name', 'Yes', 'Name of the pentest session.'],
        ['attack_path_name', 'Yes', 'The name of the attack path.'],
        ['step_name', 'Yes', 'The name of the step within the attack path.'],
    ])
    put_code('POST /determine/command\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "attack_path_name": "example_path",\n    "step_name": "exploit_step"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "command": "exploit_command --target 192.168.1.1",\n    "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n}', language='json')
    put_text(" ")
    
    # /determine/vulns
    put_markdown("## `/determine/vulns`")
    put_text("Identifies vulnerabilities for a given service and its version.")
    put_code('POST /determine/vulns\nContent-Type: application/json\n\n{\n    "service": "apache",\n    "version": "2.4.41"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "vulns": [\n        {\n            "cpe": "cpe:/a:apache:http_server:2.4.41",\n            "cves": [\n                {\n                    "cve_id": "CVE-2021-1234",\n                    "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",\n                    "weaknesses": [\n                        "CWE-79"\n                    ],\n                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",\n                    "exploit_info_links": [\n                        "https://github.com/example/exploit"\n                    ]\n                }\n            ]\n        }\n    ]\n}', language='json')
    put_text(" ")

    # /provide/command_output
    put_markdown("## `/provide/command_output`")
    put_text("Submits the output of a command executed as part of an attack path.")
    put_table([
        ['Parameter', 'Required', 'Description'],
        ['pentest_name', 'Yes', 'Name of the pentest session.'],
        ['attack_path_name', 'Yes', 'The name of the attack path.'],
        ['step_name', 'Yes', 'The name of the step within the attack path.'],
        ['command_output', 'Yes', 'The output generated by the command.'],
    ])
    put_code('POST /provide/command_output\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "attack_path_name": "example_path",\n    "step_name": "exploit_step",\n    "command_output": "Command execution result..."\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "success": true\n}', language='json')
    put_text(" ")

    # /error/command
    put_markdown("## `/error/command`")
    put_text("Handles the case where a command execution results in an error.")
    put_code('POST /error/command\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "attack_path_name": "example_path",\n    "step_name": "exploit_step",\n    "error_output": "Error details..."\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "command": "corrected_exploit_command --target 192.168.1.1",\n    "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n}', language='json')
    put_text(" ")

    # /chat_with_atom
    put_markdown("## `/chat_with_atom`")
    put_text("Facilitates a chat interface with Atom for interactive guidance and suggestions.")
    put_code('POST /chat_with_atom\nContent-Type: application/json\n\n{\n    "pentest_data": {...},\n    "conversation": [...]\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "response": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n}', language='json')
    put_text(" ")
    
    # /rethink/steps
    put_markdown("## `/rethink/steps`")
    put_text("Deletes steps from a specified step number onwards in an attack path, adds notes, and generates new steps based on the current state and notes.")
    put_table([
        ['Parameter', 'Required', 'Description'],
        ['pentest_name', 'Yes', 'Name of the pentest session.'],
        ['attack_path_name', 'Yes', 'The name of the attack path.'],
        ['from_step_number', 'Yes', 'The step number from which to delete steps onwards. (Where the first step is 1, not 0)'],
        ['notes', 'No', 'Additional notes to consider when generating new steps.'],
    ])
    put_code('POST /rethink/steps\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "attack_path_name": "example_path",\n    "from_step_number": 3,\n    "notes": "Consider using a different exploit."\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "path_name": "example_path",\n    "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",\n    "steps": [\n        {\n            "step_name": "step1",\n            "tool_name": "tool1",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        },\n        {\n            "step_name": "step2",\n            "tool_name": "tool2",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        },\n        {\n            "step_name": "step5",\n            "tool_name": "tool5",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        },\n        {\n            "step_name": "step6",\n            "tool_name": "tool6",\n            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit..."\n        }\n    ],\n    "notes": [\n        "Consider using a different exploit."\n    ]\n}', language='json')
    put_text(" ")
    
    # determine/repo_instructions
    put_markdown("## `/determine/repo_instructions`")
    put_text("Generates instructions to install and run a GitHub project based on the README content.")
    put_table([
    ['Parameter', 'Required', 'Description'],
    ['pentest_name', 'Yes', 'Name of the pentest session.'],
    ['path_name', 'Yes', 'The name of the attack path.'],
    ['step_name', 'Yes', 'The name of the step within the attack path.'],
    ])
    put_code('POST /determine/repo_instructions\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "path_name": "example_path",\n    "step_name": "install_repo"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "commands": [\n        {\n            "command": "git clone https://github.com/example/repo.git && cd repo",\n            "description": "Clone the GitHub repository and change into the project directory."\n        },\n        {\n            "command": "sudo apt-get install -y python3-pip",\n            "description": "Install Python package manager pip."\n        },\n        {\n            "command": "pip3 install -r requirements.txt",\n            "description": "Install project dependencies."\n        },\n        {\n            "command": "python3 main.py",\n            "description": "Run the main script."\n        }\n    ]\n}', language='json')
    put_text(" ")

    # /correct/service_name
    put_markdown("## `/correct/service_name`")
    put_text("Corrects the service name for a specific attack path.")
    put_table([
    ['Parameter', 'Required', 'Description'],
    ['pentest_name', 'Yes', 'Name of the pentest session.'],
    ['path_name', 'Yes', 'The name of the attack path.'],
    ['service_name', 'Yes', 'The corrected service name.'],
    ])
    put_code('POST /correct/service_name\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "path_name": "example_path",\n    "service_name": "apache"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "correction": true\n}', language='json')
    put_text(" ")

    # /correct/version_number
    put_markdown("## `/correct/version_number`")
    put_text("Corrects the version number for a specific attack path.")
    put_table([
    ['Parameter', 'Required', 'Description'],
    ['pentest_name', 'Yes', 'Name of the pentest session.'],
    ['path_name', 'Yes', 'The name of the attack path.'],
    ['version_number', 'Yes', 'The corrected version number.'],
    ])
    put_code('POST /correct/version_number\nContent-Type: application/json\n\n{\n    "pentest_name": "test_session",\n    "path_name": "example_path",\n    "version_number": "2.4.41"\n}', language='json')
    put_text("Example Response (for a successful call to this endpoint):")
    put_code('{\n    "correction": true\n}', language='json')
    put_text(" ")


def launch_app():
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    options = ["Return to menu.", "Start a new pentest.", "Resume a pentest."]
    new_or_saved = radio("Let's begin.", options=options, required=True)
    
    if new_or_saved == options[0]:
        menu()
        
    elif new_or_saved == options[1]:
        start_new_pentest()
    
    else:
        load_pentest()
        

def get_pentest_names():
    directory = "pentest_data"
    pentest_names = [file.split(".")[0] for file in os.listdir(directory) if file.endswith(".json")]
    return pentest_names


def start_new_pentest():
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    data = input_group("Basic info",[
        input('Provide a name for this pentest', name='name'),
        input('Provide the target IP address', name='target_ip')
    ])
    pentest_name = data["name"]
    target_ip = data["target_ip"]
    
    command = start_pentest(pentest_name, target_ip)["command"]
    
    nmap_output = textarea(f'Provide the output for this command: {command}', code=True, rows=18)
    
    provide_nmap_output(pentest_name, nmap_output)
    
    put_scope("progress_text")
    with use_scope("progress_text"):
        clear()
        put_markdown("#### Calculating attack surface...")
        
    put_progressbar("bar")
    set_progressbar('bar', 1 / 6)
    
    attack_surface = determine_attack_surface(pentest_name)["attack_surface"]
    
    with use_scope("progress_text"):
        clear()
        put_markdown("#### Calculating attack paths...")
        
    set_progressbar('bar', 2 / 4)
    
    attack_paths = determine_attack_paths(pentest_name)["attack_paths"]
    
    with use_scope("progress_text"):
        clear()
        put_markdown("#### Extracting extra details...")
        
    set_progressbar('bar', 3 / 4)
    
    extra_details = determine_extra_details(pentest_name)["extra_details"]
    
    with use_scope("progress_text"):
        clear()
        put_markdown("#### Done!")
    
    set_progressbar('bar', 4 / 4)
    sleep(2)
    
    pentest_main(pentest_name)
    


def load_pentest():
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    
    valid_pentest_names = get_pentest_names()
    
    pentest_name = input("Provide the name of the pentest you would like to resume", required=True)
        
    if pentest_name not in valid_pentest_names:
        clear()
        put_text(" ")
        put_text(" ")
        put_markdown("## Pentest not found")
        put_markdown("")
        put_text("The pentest name you provided could not be located in the list of saved pentests.")
        put_text(" ")
        put_row([put_button("Try again", onclick=lambda:load_pentest()), None, put_button("Return to Menu", onclick=lambda:menu())], size="20% 5% 25%")
    
    else:
        pentest_main(pentest_name)


def pentest_main(pentest_name):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    
    pentest_data = get_all_current_info(pentest_name)
    attack_surface = pentest_data["attack_surface"]
    attack_paths = pentest_data["attack_paths"]
    extra_details = pentest_data["extra_details"]
    
    put_row([put_button("Menu", onclick=lambda:menu()), None, put_button("Chat with Atom", onclick=lambda:chat_room(pentest_name, pentest_data))], size="15% 70% 15%")
    put_text(" ")
    
    put_markdown("## Attack Surface")
    put_text("Here are the open ports detected in the provided nmap scan. This is the attack surface of the target device.")
    for port_info in attack_surface:
        put_markdown(f"### Port {port_info['port_number']}: {port_info['detected_service_version']}")
        put_text(port_info["description"])
    put_text(" ")
    
    put_markdown("## Attack Paths")
    put_text("Here are the potential attack paths you could take, each representing a potential way to achieve remote code execution.")
    for attack_path in attack_paths:
        path_name = attack_path['path_name']
        put_markdown(f"#### {path_name}")
        put_text(attack_path["description"])
        put_button(f"Explore this path", onclick=partial(explore_path, pentest_name, path_name))
    put_text(" ")
    
    put_markdown("## Extra Details")
    put_text("Here are some extra data points that Atom was able to extract from the nmap scan.")
    for detail in extra_details:
        put_markdown(f"- **{detail}** : {extra_details[detail]}")
    put_text(" ")
    

def refresh_msg():
    """send new message to current session"""
    global chat_msgs
    last_idx = len(chat_msgs)
    for m in chat_msgs[last_idx:]:
        if m[0] != "human":  # only refresh message that not sent by current user
            put_markdown('`%s`: %s' % m, sanitize=True, scope='msg-box')
    # remove expired message
    if len(chat_msgs) > MAX_MESSAGES_CNT:
        chat_msgs = chat_msgs[len(chat_msgs) // 2:]


def chat_room(pentest_name, pentest_data):
    session.set_env(title='Atom.', output_max_width='60%')
    remove_footer()
    clear()
    global chat_msgs
    put_text(" ")
    put_text(" ")
    put_markdown("## Chat with Atom")
    put_scrollable(put_scope('msg-box'), height=375, keep_bottom=True)
    
    chat_msgs.append(("atom", "Hey there! I'm up to date on this pentest. Feel free to ask me anything about it."))
    put_markdown('`%s`: %s' % chat_msgs[0], sanitize=True, scope='msg-box')
    refresh_msg()

    while True:
        data = input_group('Send message', [
            input(name='msg', placeholder="Type your message..."),
            actions(name='cmd', buttons=['Send', {'label': 'Exit (Return to pentest)', 'type': 'cancel'}])
        ], validate=lambda d: ('msg', 'Message content cannot be empty') if d['cmd'] == 'Send' and not d['msg'] else None)

        if data is None:
            break

        put_markdown('`human`: %s' % data['msg'], sanitize=True, scope='msg-box')
        chat_msgs.append(("human", data['msg']))

        # Send request to AI API
        payload = {"pentest_data": pentest_data, "conversation": [{"user": m[0], "text": m[1]} for m in chat_msgs]}
        response = requests.post("http://localhost:5000/chat_with_atom", json=payload)

        # Display AI response
        ai_response = response.json()["response"]
        put_markdown('`atom`: %s' % ai_response, sanitize=True, scope='msg-box')
        chat_msgs.append(("atom", ai_response))

        refresh_msg()
    
    pentest_main(pentest_name)


def calculate_steps(pentest_name, path_name):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    put_text("Calculating exploitation steps for this attack path...")
    put_loading(shape="border", color="primary")
    put_text(" ")
    put_text("This might take a minute. Please do not refresh the page.")
    
    determine_steps(pentest_name, path_name)
    
    explore_path(pentest_name, path_name)


def calculate_command_for_step(pentest_name, path_name, step_name):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    put_text("Calculating the command for this step...")
    put_loading(shape="border", color="primary")
    put_text(" ")
    put_text("This might take a minute. Please do not refresh the page.")
    
    determine_command(pentest_name, path_name, step_name)
    
    explore_path(pentest_name, path_name)
    

def provide_command_output_gui(pentest_name, path_name, step_name, command):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    options = [
        "Yes. The command worked without error and produced a valuable output.",
        "No. An error occured or something else went wrong."
    ]
    output_type = radio("Did the command work as expected?", options=options, required=True)
    if output_type == options[0]:
        command_output = textarea(f'Provide the output for this command: {command}', code=True, rows=18)
        
        put_markdown("### Command output received.")
        put_text("Returning to the attack path screen. Please wait. ")
        put_loading(shape="border", color="primary")
        
        provide_command_output(pentest_name, path_name, step_name, command_output)
        
        sleep(2.5)
        
    else:
        data = input_group("Sorry about that. Let me rethink the command I provided.",[
            textarea(f'Provide the output error:', code=True, rows=10, name="error_output"),
            input('Notes (Describe what went wrong or what Atom should focus on):', name='notes')
        ])
        error_output = data["error_output"]
        notes = data["notes"]
        
        put_markdown("### Error output received.")
        put_text("Returning to the attack path screen. Please wait. ")
        put_loading(shape="border", color="primary")
        
        provide_command_error(pentest_name, path_name, step_name, error_output, notes=notes)
        
        sleep(2.5)
    
    explore_path(pentest_name, path_name)
    

def tool_name_to_search_query(tool_name):
    # Convert to lowercase
    query = tool_name.lower()
    # Replace spaces with plus signs
    query = query.replace(' ', '+')
    # Remove special characters
    query = re.sub(r'[^a-z0-9+]', '', query)
    return query   


def rethink_steps_gui(pentest_name, this_attack_path, path_name):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    
    steps = this_attack_path["steps"]
    options = []
    for step in steps:
        options.append(step["step_name"])
    put_text(" ")
    
    step_selection = radio("From which step would you like to rethink? The step selected will be deleted along with the future steps", options=options)
    step_number_selection = options.index(step_selection)
    sleep(0.15)
    
    notes = input("What are some notes you would like Atom to take into consideration when rethinking those steps?")
    
    clear()
    put_text(" ")
    put_text(" ")
    put_markdown("### Rethinking steps.")
    put_text("Once complete, you will be returned to the attack path screen. Please wait.")
    put_loading(shape="border", color="primary")
    
    rethink_steps(pentest_name, path_name, step_number_selection, notes=notes)
    
    sleep(0.5)
    explore_path(pentest_name, path_name)


def vuln_research(pentest_name, this_attack_path):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    put_markdown("### Doing research to find potential exploits...")
    put_text("Once complete, you will be returned to the attack path screen. Please wait.")
    put_loading(shape="border", color="primary")
    
    determine_vulnerabilities(this_attack_path["service_name"], this_attack_path["version"], pentest_name=pentest_name, attack_path_name=this_attack_path["path_name"])
    
    sleep(0.5)
    explore_path(pentest_name, this_attack_path["path_name"])


def how_to_use_this_script(pentest_name, path_name, step_name, this_attack_path):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    put_markdown("### Reading the Github repo and writing directions...")
    put_text("Once complete, you will be returned to the attack path screen. Please wait.")
    put_loading(shape="border", color="primary")
    
    determine_instructions_for_repo_script(pentest_name, path_name, step_name)
    
    sleep(0.5)
    explore_path(pentest_name, this_attack_path["path_name"])


def view_research(pentest_name, this_attack_path):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    path_name = this_attack_path["path_name"]
    put_button("Go back",onclick=lambda:explore_path(pentest_name, path_name))
    put_text(" ")
    put_markdown(f"## Research: {path_name}")
    research = this_attack_path["research"]
    pretty_json_string = json.dumps(research, indent=4, sort_keys=True)
    put_code(pretty_json_string, language="json")


def correct_service_name_gui(pentest_name, path_name):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    service_name = input("Provide the correct service name", required=True)
    
    correct_service_name(pentest_name, path_name, service_name)
    
    put_markdown("### Correcting the service name...")
    put_text("Once complete, you will be returned to the attack path screen. Please wait.")
    put_loading(shape="border", color="primary")
    
    sleep(0.5)
    explore_path(pentest_name, path_name)


def correct_version_number_gui(pentest_name, path_name):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    put_text(" ")
    put_text(" ")
    version_number = input("Provide the correct service name", required=True)
    
    correct_version_number(pentest_name, path_name, version_number)
    
    put_markdown("### Correcting the version number...")
    put_text("Once complete, you will be returned to the attack path screen. Please wait.")
    put_loading(shape="border", color="primary")
    
    sleep(0.5)
    explore_path(pentest_name, path_name)


def explore_path(pentest_name, path_name):
    session.set_env(title='Atom.', output_max_width='95%')
    remove_footer()
    clear()
    
    put_row([
        put_button("Menu", onclick=lambda:menu()), 
        put_button(pentest_name, onclick=lambda:pentest_main(pentest_name)),
        None, 
        put_button("Chat with Atom", onclick=lambda:chat_room(pentest_name, pentest_data))
        ], 
        size="10% 10% 70% 15%")
    put_text(" ")
    
    pentest_data = get_all_current_info(pentest_name)
    
    this_attack_path = None
    for attack_path in pentest_data["attack_paths"]:
        if attack_path["path_name"] == path_name:
            this_attack_path = attack_path
    
    put_markdown(f"# {this_attack_path['path_name']}")
    put_text(this_attack_path["description"])
    put_text(" ")
    
    put_markdown("## Service Version Information")
    put_markdown(f"#### Service: {this_attack_path['service_name']}")
    put_button("This service name is not correct", onclick=lambda:correct_service_name_gui(pentest_name, this_attack_path["path_name"]))
    put_markdown(f"#### Version: {this_attack_path['version']}")
    put_button("This version number is not correct", onclick=lambda:correct_version_number_gui(pentest_name, this_attack_path["path_name"]))
    put_text(" ")
    
    put_markdown("## Research On Existing Vulnerabilities and Exploits")
    if "research" not in this_attack_path:
        put_button("Perform vulnerability research", onclick=lambda: vuln_research(pentest_name, this_attack_path))
    else:
        put_button("Redo vulnerability research", onclick=lambda: vuln_research(pentest_name, this_attack_path))
        put_button("View completed research", onclick=lambda:view_research(pentest_name, this_attack_path))
    put_text(" ")
    
    put_markdown("## Exploitation Steps")
    if "steps" not in this_attack_path:
        put_button("Calculate steps", onclick=lambda: calculate_steps(pentest_name, path_name))
    else:
        put_button("Rethink steps using a different approach", onclick=lambda: rethink_steps_gui(pentest_name, this_attack_path, path_name))
        step_number = 1
        steps_without_output = set()  # Set to remember steps that meet the specific condition
        previous_step_has_command_and_output = False  # Flag to track if the previous step has a command and output

        for step in this_attack_path["steps"]:
            step_name = step['step_name']
            put_markdown(f"#### Step {step_number}: {step_name}")
            put_markdown(f"- Description: {step['description']}")
            tool_name = step['tool_name']
            put_row([put_markdown(f"- Recommended tool:"), put_link(tool_name, url=f"https://www.google.com/search?q=how+to+install+{tool_name_to_search_query(tool_name)}", new_window=True)], size="15% 50%")

            # Check if 'command' is present but 'output' is not
            if "command" in step and "output" not in step:
                # If this condition hasn't been reported for this step
                if step_number not in steps_without_output:
                    command = step["command"]
                    put_markdown(f"- Command: `{command}`")
                    put_markdown(f"- Command Description: {step['command_description']}")

                # Show the "provide output" button if the previous step has a command and output
                if previous_step_has_command_and_output or step_number == 1:
                    put_row([None, put_button("Provide the output of the above command", onclick=partial(provide_command_output_gui, pentest_name, path_name, step_name, command))], size="2% 50%")
                    steps_without_output.add(step_number)  # Remember this step as the first one with no command output
                previous_step_has_command_and_output = False  # Reset the flag since the current step doesn't have output
                
            elif "command" in step:
                # If there's a command (and implicitly there is output, due to the above condition)
                command = step["command"]
                put_markdown(f"- Command: `{command}`")
                put_markdown(f"- Command Description: {step['command_description']}")
                previous_step_has_command_and_output = True  # Set the flag to True for the next step
            
            if not "command" in step:
                # If the current step doesn't have a command
                if previous_step_has_command_and_output or step_number == 1:
                    if "https://" in tool_name.lower():
                        if "https://github.com" in step['description']:
                            put_row([None, put_button("How do I use this script?", onclick=partial(how_to_use_this_script, pentest_name, path_name, step_name, this_attack_path))], size="2% 50%")
                    else:
                        put_row([None, put_button("Determine command to use", onclick=partial(calculate_command_for_step, pentest_name, path_name, step_name))], size="2% 50%")
                previous_step_has_command_and_output = False  # Reset the flag since the current step doesn't have a command

            # Increment step number for the next iteration
            step_number += 1
    
            


if __name__ == '__main__':
  pywebio.config(title=app_name)
  start_server(menu, port=port, debug=debug)
