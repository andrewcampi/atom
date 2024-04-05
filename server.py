from flask import Flask, request, jsonify, render_template
import os
import requests
import cloudscraper
from helper.llm_endpoint_chatgpt import llm_endpoint_call, llm_chat_endpoint
from helper.general_helpers import *
from helper.vuln_lookup import *


app = Flask(__name__)

pentest_data_dir = 'pentest_data'
os.makedirs(pentest_data_dir, exist_ok=True)


@app.route('/start', methods=['POST'])
def start_pentest():
    data = request.get_json()
    pentest_name = data.get('pentest_name')
    target_ip = data.get('target_ip')

    if not pentest_name or not target_ip:
        return jsonify({'error': 'pentest_name and target_ip are required'}), 400

    this_pentest_data = {"pentest_name": pentest_name, "target_ip": target_ip, "can_load_from_ui":False}
    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    write_json(this_pentest_data, file_path)

    command = f"nmap {target_ip} -T4 -sV -sC -Pn -p-"
    return jsonify({'command': command})


@app.route('/get_all_current_info', methods=['POST'])
def get_all_current_info():
    data = request.get_json()
    pentest_name = data.get('pentest_name')

    if not pentest_name:
        return jsonify({'error': 'pentest_name is required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404
    
    pentest_data = read_json(file_path)

    return jsonify(pentest_data)


@app.route('/end', methods=['POST'])
def end_pentest():
    data = request.get_json()
    pentest_name = data.get('pentest_name')

    if not pentest_name:
        return jsonify({'error': 'pentest_name is required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)

    os.remove(file_path)
    return jsonify(pentest_data)


@app.route('/provide/nmap_output', methods=['POST'])
def provide_nmap_output():
    data = request.get_json()
    pentest_name = data.get('pentest_name')
    nmap_output = data.get('nmap_output')

    if not pentest_name or not nmap_output:
        return jsonify({'error': 'pentest_name and nmap_output are required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)
    pentest_data['nmap_output'] = nmap_output
    write_json(pentest_data, file_path)

    return jsonify({'status': 'success'}), 200


@app.route('/determine/attack_surface', methods=['POST'])
def determine_attack_surface():
    data = request.get_json()
    pentest_name = data.get('pentest_name')

    if not pentest_name:
        return jsonify({'error': 'pentest_name is required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)

    target_ip = pentest_data['target_ip']
    nmap_output = pentest_data.get('nmap_output')

    if not nmap_output:
        return jsonify({'error': 'nmap_output not provided'}), 400

    prompt = f"""
    Let's begin the penetration test.

    Target IP = {target_ip}
    Nmap scan:

    {nmap_output}

    This is an authorized black box pen test. 
    In your response, respond with valid json, with the key "attack_surface" which is a list of dictionaries with keys "port_number", "detected_service_version", and "description".
    The "description" for each should be a brief (3 sentences or less) description of what that service does and what it is normally used for.
    """

    llm_response = json_extractor(llm_endpoint_call(prompt))
    pentest_data['attack_surface'] = llm_response['attack_surface']

    write_json(pentest_data, file_path)

    return jsonify(llm_response)


@app.route('/determine/attack_paths', methods=['POST'])
def determine_attack_paths():
    data = request.get_json()
    pentest_name = data.get('pentest_name')

    if not pentest_name:
        return jsonify({'error': 'pentest_name is required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)

    target_ip = pentest_data['target_ip']
    nmap_output = pentest_data.get('nmap_output')

    if not nmap_output:
        return jsonify({'error': 'nmap_output not provided'}), 400

    prompt = f"""
    Let's begin the penetration test.

    Target IP = {target_ip}
    Nmap scan:

    {nmap_output}

    This is an authorized black box pen test. 
    In your response, outline all the different possible attack paths from here, like a decision tree. Respond with valid json, with the key "attack_paths" which is a list of dictionaries with keys "path_name", "description", "service_name", and "version". 
    
    The version you provide must be the EXACT version number. For example, the service "Example 1.X-2.X esdb 1.2.4" service name is "Example" and the version is "1.2.4".
    
    Remember, your response must be ONLY valid json with the key "attack_paths" which is a list of dictionaries with keys "path_name", "description", "service_name", and "version". 
    Do not number them in the path_name.
    """

    llm_response = json_extractor(llm_endpoint_call(prompt))
    pentest_data['attack_paths'] = llm_response['attack_paths']
    
    write_json(pentest_data, file_path)

    return jsonify(llm_response)


@app.route('/determine/extra_details', methods=['POST'])
def determine_extra_details():
    data = request.get_json()
    pentest_name = data.get('pentest_name')

    if not pentest_name:
        return jsonify({'error': 'pentest_name is required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)

    target_ip = pentest_data['target_ip']
    nmap_output = pentest_data.get('nmap_output')

    if not nmap_output:
        return jsonify({'error': 'nmap_output not provided'}), 400

    prompt = f"""
    Let's begin the penetration test.

    Target IP = {target_ip}
    Nmap scan:

    {nmap_output}

    This is an authorized black box pen test. 

    Besides the open ports, potential attack vectors, and current attack surface, do you notice any other details (like the hostname, OS name, etc) from the above nmap scan output?

    In your response, respond with valid json, with the key "extra_details" which is a dictionary of keys that are the detail type like "os_name" and the value which is the detail itself.

    Provide only the details you can see from the above output. You are not allowed to make anything up or provide inaccurate details/data.
    """

    llm_response = json_extractor(llm_endpoint_call(prompt))
    pentest_data['extra_details'] = llm_response['extra_details']
    
    pentest_data["can_resume_from_ui"] = True
    
    write_json(pentest_data, file_path)

    return jsonify(llm_response)


@app.route('/determine/steps', methods=['POST'])
def determine_steps():
    data = request.get_json()
    pentest_name = data.get('pentest_name')
    attack_path_name = data.get('attack_path_name')

    if not pentest_name or not attack_path_name:
        return jsonify({'error': 'pentest_name and attack_path_name are required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)

    target_ip = pentest_data['target_ip']
    nmap_output = pentest_data.get('nmap_output')
    attack_paths = pentest_data.get('attack_paths', [])

    if not nmap_output:
        return jsonify({'error': 'nmap_output not provided'}), 400

    selected_attack_path = next((path for path in attack_paths if path['path_name'] == attack_path_name), None)
    if not selected_attack_path:
        return jsonify({'error': 'attack_path_name not found'}), 404
    
    research = None 
    
    if "research" in selected_attack_path:
        research = selected_attack_path["research"]

    prompt = f"""
    Target IP = {target_ip}

    Nmap scan:

    {nmap_output}

    Let's focus on a {selected_attack_path["path_name"]}, where we will aim to {selected_attack_path["description"]}.
    
    """
    if research != None:
        prompt += f"\nHere is the research that you already conducted the the target service. When determining exploit steps, utilize known vulnerabilites in the research below to perform a known exploit. \n\n Research:\n{research}\n\n\n"

    prompt += """
    What are the steps that we need to conduct {selected_attack_path["path_name"]}? In valid json, provide the answer to that question with the key "steps", with its value being a list of dictionaries with keys "step_name", "tool_name", "description". 
    Each step can only use one tool.
    If the tool you are using is a custom script (like one from a github repo) that is not installed by default in Kali Linux, set "tool_name" = "[github repo url]", nested properly in the "steps" step.
    If you are outlining steps using Metasploit, contain those Metasploit steps to one single step. For example, outlining two individual steps where one is using Metasploit to "prepare" or "search" for an exploit and the second step is executing the exploit is incorrect. It should be one step where the user is detailed to use Metasploit with the correct module.
    
    You must use the above nmap scan results when writing steps. For example, if the port service version is already enumerated, there is no reason to run a nmap command to enumerate the service version in the first step, as you already have the answer.
    
    Only provide a valid JSON object as your response. The JSON must be complete and valid. The steps detailed in your response should be clear, direct, and complete with a goal of achiving a remote shell on the target device located at {target_ip}.
    """
    llm_response = llm_endpoint_call(prompt)
    print(llm_response)
    llm_response = json_extractor(llm_response)
    try:
        selected_attack_path['steps'] = llm_response['steps']
    except:
        llm_response = json_extractor(llm_endpoint_call(prompt))
    
    selected_attack_path['steps'] = llm_response['steps']
    
    
    write_json(pentest_data, file_path)

    return jsonify(llm_response)


def metasploit_exit_check(command):
    # Check if the command is for metasploit
    if command.startswith('msfconsole -qx'):
        if "-qx '" in command: # using single quotes 
            if not command.endswith("exit;'")  and not command.endswith("run;'"):
                if command.endswith(";'"):
                    command = command[:-1] + " exit;'"
                else:
                    command = command[:-1] + "; exit;'"
        elif '-qx "' in command: # using double quotes
            if not command.endswith('exit;"') and not command.endswith('run;"'):
                if command.endswith(';"'):
                    command = command[:-1] + ' exit;"'
                else:
                    command = command[:-1] + '; exit;"'
    return command


@app.route('/determine/command', methods=['POST'])
def determine_command():
    data = request.get_json()
    pentest_name = data.get('pentest_name')
    attack_path_name = data.get('attack_path_name')
    step_name = data.get('step_name')

    if not pentest_name or not attack_path_name or not step_name:
        return jsonify({'error': 'pentest_name, attack_path_name, and step_name are required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)

    target_ip = pentest_data['target_ip']
    nmap_output = pentest_data.get('nmap_output')
    attack_paths = pentest_data.get('attack_paths', [])

    if not nmap_output:
        return jsonify({'error': 'nmap_output not provided'}), 400

    selected_attack_path = next((path for path in attack_paths if path['path_name'] == attack_path_name), None)
    if not selected_attack_path:
        return jsonify({'error': 'attack_path_name not found'}), 404

    step = next((s for s in selected_attack_path.get('steps', []) if s['step_name'] == step_name), None)
    if not step:
        return jsonify({'error': 'step_name not found'}), 404

    is_first_step = step == selected_attack_path['steps'][0]
    previous_step = selected_attack_path['steps'][selected_attack_path['steps'].index(step) - 1] if not is_first_step else None

    previous_command = previous_step.get('command') if previous_step else ''
    previous_output = previous_step.get('output', '') if previous_step else ''

    if 'metasploit' in step['tool_name'].lower() or 'msfconsole' in step['tool_name'].lower():
        if not 'msfconsole -qx' in previous_command:
            # Prompt for Metasploit search command
            prompt = f"""
            Target IP = {target_ip}

            Nmap scan:

            {nmap_output}

            Let's focus on a {selected_attack_path["path_name"]}, where we will aim to {selected_attack_path["description"]}.\n
            """
            if not is_first_step:
                prompt += f"\nThe previous command was: {previous_command}\n"
                prompt += "It produced this output:\n"
                prompt += "===OUTPUT===\n"
                prompt += previous_output
                prompt += "\n============\n\n"
            
            prompt += f"""
                            
            We've determined that the next step in this attack path is to {step["step_name"]}. We must use {step["tool_name"]} in an effort to {step["description"]}.

            Based on the command and its output I provided, along with the other information above, what is one-liner Metasploit command that will show a list of the avaiable, relevant exploit module names? 
                            
            It should be something like this: msfconsole -qx "search eternalblue" (but relevant to the service we are trying to exploit as detailed above).
                            
            Your response must be formatted in valid JSON with the key "metasploit_search_command".
                            
            Your command cannot have any placeholder or unknowns in it. It must work as is, so that it can be directly copied and paste.
                            
            Only provide the valid json as your response as requested. 
            """
            llm_response = json_extractor(llm_endpoint_call(prompt))
            metasploit_search_command = llm_response['metasploit_search_command']

            # Restructure steps for Metasploit
            step['command'] = metasploit_exit_check(metasploit_search_command)
            step['command_description'] = 'Use this command to find the corresponding module that would potentially exploit the target service.'
            new_step = {'step_name': 'Run Metasploit Exploit', 'description': "Use the discovered Metasploit module to exploit the target service.", 'tool_name': 'Metasploit'}
            selected_attack_path['steps'].insert(selected_attack_path['steps'].index(step) + 1, new_step)
            
            write_json(pentest_data, file_path)

            return jsonify({'command': metasploit_search_command, 'note': 'Metasploit is being used, so I needed to restructure the steps. Please make a request to "/get_all_current_info" to resync your steps.'})

        else:
            # Prompt for Metasploit search command
            prompt = f"""
            Target IP = {target_ip}

            Nmap scan:

            {nmap_output}

            Let's focus on a {selected_attack_path["path_name"]}, where we will aim to {selected_attack_path["description"]}.\n
            """
            if not is_first_step:
                prompt += f"\nThe previous command was: {previous_command}\n"
                prompt += "It produced this output:\n"
                prompt += "===OUTPUT===\n"
                prompt += previous_output
                prompt += "\n============\n\n"
            prompt += f"""
                            
            We've determined that the next step in this attack path is to {step["step_name"]}. We must use {step["tool_name"]} in an effort to {step["description"]}.

            Based on the command and its output I provided, along with the other information above, what is one-liner Metasploit command that select and run the correct exploit module, relevant exploit module names? 
                            
            It should be something like this: msfconsole -qx "use [module_name]; set RHOST [target_ip]; run;" (but relevant to the service we are trying to exploit as detailed above).
                            
            Your response must be formatted in valid JSON with the key "metasploit_exploit_command".
                            
            Your command cannot have any placeholder or unknowns in it. It must work as is, so that it can be directly copied and paste.
                            
            Only provide the valid json as your response as requested. 
            """
            llm_response = json_extractor(llm_endpoint_call(prompt))
            metasploit_exploit_command = llm_response['metasploit_exploit_command']

            step['command'] = metasploit_exit_check(metasploit_exploit_command)
            step['command_description'] = 'Use this command to run the specific exploit module against the target.'
            
            write_json(pentest_data, file_path)

            return jsonify({'command': metasploit_exploit_command})

    else:
        prompt = f"""
        Target IP = {target_ip}

        Nmap scan:

        {nmap_output}

        Let's focus on a {selected_attack_path["path_name"]}, where we will aim to {selected_attack_path["description"]}.\n
        """
        if not is_first_step:
            prompt += f"\nThe previous command was: {previous_command}\n"
            prompt += "It produced this output:\n"
            prompt += "===OUTPUT===\n"
            prompt += previous_output
            prompt += "\n============\n\n"
        prompt += f"""
                        
        We've determined that the next step in this attack path is to {step["step_name"]}. We must use {step["tool_name"]} in an effort to {step["description"]}.

        Based on the command and its output I provided, along with the other information above, what is the exact command to use? Remember, the target IP address is {target_ip}. As your response, provide valid json with keys "tool_name", "command", and "description". 
                        
        Your command cannot have any placeholder or unknowns in it. It must work as is, so that it can be directly copied and paste.

        Only provide the valid json as your response as requested. 
        """
        llm_response = json_extractor(llm_endpoint_call(prompt))
        command = metasploit_exit_check(llm_response['command'])
        description = llm_response['description']

        step['command'] = command
        step['command_description'] = description
        
        write_json(pentest_data, file_path)

        return jsonify({'command': command, 'description': description})


@app.route('/provide/command_output', methods=['POST'])
def provide_command_output():
    data = request.get_json()
    pentest_name = data.get('pentest_name')
    attack_path_name = data.get('attack_path_name')
    step_name = data.get('step_name')  # Use step_name instead of step_index
    command_output = data.get('command_output')

    if not pentest_name or not attack_path_name or not step_name or not command_output:
        return jsonify({'error': 'pentest_name, attack_path_name, step_name, and command_output are required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)
    attack_paths = pentest_data.get('attack_paths', [])

    selected_attack_path = next((path for path in attack_paths if path['path_name'] == attack_path_name), None)
    if not selected_attack_path:
        return jsonify({'error': 'attack_path_name not found'}), 404

    steps = selected_attack_path.get('steps', [])
    # Find the step by step_name instead of using step_index
    step = next((step for step in steps if step['step_name'] == step_name), None)
    if not step:
        return jsonify({'error': 'step_name not found'}), 404

    step['output'] = command_output

    write_json(pentest_data, file_path)

    return jsonify({'success': True})


@app.route('/error/command', methods=['POST'])
def error_command():
    data = request.get_json()
    pentest_name = data.get('pentest_name')
    attack_path_name = data.get('attack_path_name')
    step_name = data.get('step_name')
    error_output = data.get('error_output')
    
    try:
        notes = data.get('notes')
    except:
        notes = None

    if not pentest_name or not attack_path_name or not step_name or not error_output:
        return jsonify({'error': 'pentest_name, attack_path_name, step_name, and error_output are required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)

    target_ip = pentest_data['target_ip']
    nmap_output = pentest_data.get('nmap_output')
    attack_paths = pentest_data.get('attack_paths', [])

    if not nmap_output:
        return jsonify({'error': 'nmap_output not provided'}), 400

    selected_attack_path = next((path for path in attack_paths if path['path_name'] == attack_path_name), None)
    if not selected_attack_path:
        return jsonify({'error': 'attack_path_name not found'}), 404

    step = next((s for s in selected_attack_path.get('steps', []) if s['step_name'] == step_name), None)
    if not step:
        return jsonify({'error': 'step_name not found'}), 404

    prompt = f"""
    Target IP = {target_ip}

    Nmap scan:

    {nmap_output}

    Let's focus on a {selected_attack_path["path_name"]}, where we will aim to {selected_attack_path["description"]}.

    We've determined that the first step in this attack path is to {step["step_name"]}. We will use {step["tool_name"]} in an effort to {step["description"]}.
                    
    You told me to run the following command: {step["command"]}
    However, it produced the following error output: 
    ===
    {error_output}
    ===
    
    """
    
    prompt += f"""

    Learning from the above error output, what is the correct command? Remember, the target IP address is {target_ip}. As your response, provide valid json with keys "tool_name", "command", and "description". 
                    
    In the event that your command is using Metasploit, you must craft a one-liner msfconsole command that, in one line, like this example: msfconsole -qx "search eternalblue;use 0;set RHOST 10.0.2.4;run"
                    
    Your command cannot have any placeholder or unknowns in it. It must work as is, so that it can be directly copied and paste.

    Only provide the valid json as your response as requested. 
    """
    
    if notes != None:
        prompt += f"\n\nThe user of the command that caused an error provided these notes for you to reference when crafting your output:\n {notes}"

    llm_response = json_extractor(llm_endpoint_call(prompt))
    step['command'] = llm_response['command']
    step['command_description'] = llm_response['description']

    write_json(pentest_data, file_path)

    return jsonify({'command': llm_response['command'], 'description': llm_response['description']})


def remove_outputs(pentest_data):
    keys_to_delete = [key for key in pentest_data if "output" in key.lower() and key.lower() != "nmap_output"]
    for key in keys_to_delete:
        del pentest_data[key]
    
    for key, value in pentest_data.items():
        if isinstance(value, dict):
            pentest_data[key] = remove_outputs(value)
    
    return pentest_data


@app.route('/chat_with_atom', methods=['POST'])
def chat_with_atom():
    data = request.get_json()
    pentest_data = data.get('pentest_data')
    chat_content = data.get('conversation')

    if not pentest_data:
        return jsonify({'error': 'pentest_data is required'}), 400

    if not chat_content:
        return jsonify({'error': 'conversation is required'}), 400

    # Remove outputs from pentest_data
    pentest_data = remove_outputs(pentest_data)

    # Format chat_content for llm_chat_endpoint
    formatted_chat_content = [
        {"role": "assistant" if msg["user"] == "atom" else "user", "content": msg["text"]}
        for msg in chat_content
    ]

    # Get response from llm_chat_endpoint
    llm_response = llm_chat_endpoint(pentest_data, formatted_chat_content)

    return jsonify({'response': llm_response})


def exploit_to_search_query(exploit_query):
    # Convert to lowercase
    query = exploit_query.lower()
    # Replace spaces with plus signs
    query = query.replace(' ', '+')
    # Remove special characters
    query = re.sub(r'[^a-z0-9+]', '', query)
    query = "https://www.bing.com/search?q=" + query
    return query   


@app.route('/determine/vulns', methods=['POST'])
def determine_vulns():
    data = request.get_json()
    component = data.get('service')
    version = data.get('version')
    
    try:
        pentest_name = data.get('pentest_name')
    except:
        pentest_name = None
    
    try:
        attack_path_name = data.get('attack_path_name')
    except:
        attack_path_name = None
    
    if pentest_name != None:
        file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
        if not os.path.exists(file_path):
            return jsonify({'error': 'pentest data not found'}), 404

        pentest_data = read_json(file_path)

    cpe_strings = find_cpes(component, version)
    
    response = {
        "vulns": [],
        "references": [], 
        "exploitdb": {}
    }
    
    if cpe_strings:
        for cpe_string in cpe_strings:
            results = fetch_cve_details([cpe_string])
            if results:
                cpe_vulns = {
                    "cpe": cpe_string,
                    "cves": []
                }
                for result in results:
                    cve_id = result["CVE ID"]
                    github_urls = list(set(fetch_github_urls(cve_id)))
                    exploit_info = []
                    for url in github_urls:
                        exploit_info.append({"url":url, "content": "URL was not requested yet."})
                    cve_info = {
                        "cve_id": cve_id,
                        "description": result["Description"],
                        "weaknesses": list(set(result["Weaknesses"].split(", ") if result["Weaknesses"] else [])),
                        "link": result["Link"],
                        "exploit_info_links": list(set(github_urls))
                    }
                    cpe_vulns["cves"].append(cve_info)
                response["vulns"].append(cpe_vulns)
    
    # Need to trim cves if there are too many (context window token issues)
    for vuln in response["vulns"]:
        print("len:", len(vuln["cves"]))
        if len(vuln["cves"]) > 10:
            vuln["cves"] = vuln["cves"][:10]
            print("Shortened!")
    
    download_links = None #search_and_extract_download_links(component)
    response["references"] = []
    if download_links:
        for url in download_links:
            response["references"].append({"url":url, "data":get_download(url)})
    
    scraper = cloudscraper.create_scraper()
    search_url = exploit_to_search_query(str(component + " " + version + " exploit exploitdb"))
    exploit_db_url = get_exploitdb_link(scraper, search_url)
    if exploit_db_url != None:
        response["exploitdb"] = exploitdb_page_to_json(scraper, exploit_db_url)
    
    
    # If the client provided an attack path name in their request ...
    if attack_path_name != None and pentest_name != None:
        # ... save the data in their pentest data file under the correct attack path.  
        for attack_path in pentest_data["attack_paths"]:
            if attack_path["path_name"] == attack_path_name: # Found the correct path
                attack_path["research"] = response
                write_json(pentest_data, f"pentest_data/{pentest_name}.json")
        
    return jsonify(response)


@app.route('/rethink/steps', methods=['POST'])
def rethink_steps():
    data = request.get_json()
    pentest_name = data.get('pentest_name')
    attack_path_name = data.get('attack_path_name')
    from_step_number = data.get('from_step_number')
    notes = data.get('notes')

    if not pentest_name or not attack_path_name or from_step_number is None:
        return jsonify({'error': 'pentest_name, attack_path_name, and from_step_number are required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)

    target_ip = pentest_data['target_ip']
    nmap_output = pentest_data.get('nmap_output')
    attack_paths = pentest_data.get('attack_paths', [])

    if not nmap_output:
        return jsonify({'error': 'nmap_output not provided'}), 400

    selected_attack_path = next((path for path in attack_paths if path['path_name'] == attack_path_name), None)
    if not selected_attack_path:
        return jsonify({'error': 'attack_path_name not found'}), 404

    # Delete steps from from_step_number onwards
    selected_attack_path['steps'] = selected_attack_path['steps'][:from_step_number]

    # Append the notes to the existing notes list or create a new one
    if 'notes' in selected_attack_path:
        selected_attack_path['notes'].append(notes)
    else:
        selected_attack_path['notes'] = [notes]
        
    research = None 
    
    if "research" in selected_attack_path:
        research = selected_attack_path["research"]

    # Generate new steps based on the current state
    prompt = f"""
    Target IP = {target_ip}

    Nmap scan:

    {nmap_output}

    Let's focus on a {selected_attack_path["path_name"]}, where we will aim to {selected_attack_path["description"]}.
    
    """
    
    if research != None:
        prompt += f"\nHere is the research that you already conducted the the target service. When determining exploit steps, utilize known vulnerabilites in the research below to perform a known exploit. \n\n Research:\n{research}\n\n\n"
  
    prompt += """
    
    
    The current steps in this attack path are:
    """

    for index, step in enumerate(selected_attack_path['steps']):
        prompt += f"{index + 1}. {step['step_name']}: {step['description']}\n"

    prompt += f"""
    Notes:
    {selected_attack_path['notes']}

    Based on the current state and notes, what are the next steps to continue this attack path? In valid json, provide the answer to that question with the key "steps", with its value being a list of dictionaries with keys "step_name", "tool_name", and "description". 
    Each step can only use one tool.
    Do not repeat the steps already in this attack path. You must continue from where the steps leave off. 
    Make sure to reference the "notes" above when making planning new steps.
    If you are outlining steps using Metasploit, contain those Metasploit steps to one single step. For example, outlining two individual steps where one is using Metasploit to "prepare" or "search" for an exploit and the second step is executing the exploit is incorrect. It should be one step where the user is detailed to use Metasploit with the correct module.
    Only provide JSON as your response. The steps detailed in your response should be clear, direct, and complete with a goal of achiving a remote shell on the target device located at {target_ip}.
    """

    llm_response = json_extractor(llm_endpoint_call(prompt))
    
    selected_attack_path['steps'].extend(llm_response['steps'])

    write_json(pentest_data, file_path)

    return jsonify(selected_attack_path)


def get_download(url):
    """
    Given a URL that produces a download, returns the modified content of the .txt file it requested from the URL,
    after processing it according to specified rules (removing lines between "-----BEGIN" and "-----END" markers,
    and removing duplicate lines).
    
    :param url: The URL to fetch the .txt file from.
    :return: The modified content of the .txt file as a string.
    """
    try:
        response = requests.get(url)
        response.raise_for_status() # Raises HTTPError for bad responses
        
        # Split the content into lines
        lines = response.text.splitlines()
        
        # Initialize variables for the BEGIN and END line numbers
        sign_begin_line_number = None
        sign_end_line_number = None
        
        # Search for the BEGIN and END markers
        for i, line in enumerate(lines):
            if line.startswith("-----BEGIN") and sign_begin_line_number is None:
                sign_begin_line_number = i
            elif line.startswith("-----END") and sign_begin_line_number is not None:
                sign_end_line_number = i
                break  # Stop searching once both markers are found
        
        # If both markers are found, remove the lines between them, inclusive
        if sign_begin_line_number is not None and sign_end_line_number is not None:
            del lines[sign_begin_line_number:sign_end_line_number + 1]
        
        # Remove duplicate lines, preserving order
        seen = set()
        lines_no_duplicates = [line for line in lines if not (line in seen or seen.add(line))]
        
        # Join the lines back into a single string and return
        return "\n".join(lines_no_duplicates)
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return None


def extract_github_repo_link(step):
    description = step["description"]
    tool_name = step["too_name"]
    
    pattern = r'https://github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-_]+'
    
    url = re.search(pattern, tool_name)
    if url:
        url = url.group()
        return url
    else:
        url = re.search(pattern, description)
        if url:
            url = url.group()
        else:
            return None


def get_readme_content(repo_link):
    base_replaced = repo_link.replace("https://github.com/", "https://raw.githubusercontent.com/")
    # Append the specific path to the README.md file in the main branch
    raw_link = base_replaced + "/main/README.md"
    # Request the page
    scraper = cloudscraper.create_scraper()
    readme_content = scraper.get(raw_link).text
    # Return it
    return readme_content


@app.route('/determine/repo_instructions', methods=['POST'])
def determine_repo_instructions():
    data = request.get_json()
    pentest_name = data.get('pentest_name')
    path_name = data.get('path_name')
    step_name = data.get('step_name')
    
    if not pentest_name:
        return jsonify({'error': 'pentest_name is required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404
    
    pentest_data = read_json(file_path)
    
    this_attack_path = pentest_data["attack_paths"][path_name]
    
    this_step = None
    for step in this_attack_path["steps"]:
        if step["step_name"] == step_name:
            this_step = step
    
    if this_step == None:
        return jsonify({'error': 'The given step name was not found in the saved pentest data attack path'}), 404
    
    repo_link = extract_github_repo_link(this_step)
    
    readme = get_readme_content(repo_link)
    
    target_ip = pentest_data["target_ip"]
    
    prompt = f"""
    target_ip: {target_ip}
    repo_link: {repo_link}
    
    ====START readme_content====
    {readme}
    ===END readme_content====
    
    Based on the above readme content, write the steps in valid JSON format to install and run this github project. Remeber, the target IP address is {target_ip}.
    
    You must respond with valid JSON, with key "commands" with a value of type list of dicts. These dicts have keys "command" which is the exact command to use, and "description" which is a very brief description of what that command does in one sentence.
    
    Your steps must include installing any dependencies, including cloning the github repo with "git clone [repo_link].git && cd [repo_name]". Assume that the user is using Ubuntu and already ran "sudo apt-get update && sudo apt-get upgrade -y", but that is all you can assume they have installed. 
    """
    
    llm_response = json_extractor(llm_endpoint_call(prompt))
    
    this_step["command"] = "See 'commands' below."
    
    this_step["commands"] = llm_response["commands"]
    
    write_json(pentest_data, file_path)

    return jsonify(llm_response)
    
    
@app.route('/correct/service_name', methods=['POST'])
def correct_the_service_name():
    data = request.get_json()
    pentest_name = data.get('pentest_name')
    path_name = data.get('path_name')
    service_name = data.get('service_name')
    
    if not pentest_name:
        return jsonify({'error': 'pentest_name is required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)
    
    path_index = 0
    for path in pentest_data["attack_paths"]:
        if path["path_name"] == path_name:
            break
        path_index += 1
    
    try:
        pentest_data["attack_paths"][path_index]["service_name"] = service_name 
        write_json(pentest_data, file_path)

        return jsonify({"correction":True})

    except:
        
        return jsonify({"correction":False})


@app.route('/correct/version_number', methods=['POST'])
def correct_the_version_number():
    data = request.get_json()
    pentest_name = data.get('pentest_name')
    path_name = data.get('path_name')
    version_number = data.get('version_number')
    
    if not pentest_name:
        return jsonify({'error': 'pentest_name is required'}), 400

    file_path = os.path.join(pentest_data_dir, f"{pentest_name}.json")
    if not os.path.exists(file_path):
        return jsonify({'error': 'pentest data not found'}), 404

    pentest_data = read_json(file_path)
    
    path_index = 0
    for path in pentest_data["attack_paths"]:
        if path["path_name"] == path_name:
            break
        path_index += 1
    
    try:
        pentest_data["attack_paths"][path_index]["version"] = version_number
        write_json(pentest_data, file_path)

        return jsonify({"correction":True})

    except:
        return jsonify({"correction":False})


if __name__ == '__main__':
    app_instance = app
    app_instance.run(host="0.0.0.0", port=5000, debug=True)