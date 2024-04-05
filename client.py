import requests
from helper.project_info import *

# Server URL
BASE_URL = "http://localhost:5000"

def start_pentest(pentest_name, target_ip):
    url = f"{BASE_URL}/start"
    payload = {"pentest_name": pentest_name, "target_ip": target_ip}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.json()['error']}")


def get_all_current_info(pentest_name):
    url = f"{BASE_URL}/get_all_current_info"
    payload = {"pentest_name": pentest_name}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.json()['error']}")


def end_pentest(pentest_name):
    url = f"{BASE_URL}/end"
    payload = {"pentest_name": pentest_name}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.json()['error']}")


def provide_nmap_output(pentest_name, nmap_output):
    url = f"{BASE_URL}/provide/nmap_output"
    payload = {"pentest_name": pentest_name, "nmap_output": nmap_output}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        print("Nmap output provided successfully.")
    else:
        print(f"Error: {response.json()['error']}")


def determine_attack_surface(pentest_name):
    url = f"{BASE_URL}/determine/attack_surface"
    payload = {"pentest_name": pentest_name}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.json()['error']}")


def determine_attack_paths(pentest_name):
    url = f"{BASE_URL}/determine/attack_paths"
    payload = {"pentest_name": pentest_name}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.json()['error']}")


def determine_extra_details(pentest_name):
    url = f"{BASE_URL}/determine/extra_details"
    payload = {"pentest_name": pentest_name}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.json()['error']}")


def determine_steps(pentest_name, attack_path_name):
    url = f"{BASE_URL}/determine/steps"
    
    payload = {"pentest_name": pentest_name, "attack_path_name": attack_path_name}
    if allow_sniper_command_recommendations:
        payload["use_sniper"] = True

    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.json()['error']}")


def determine_command(pentest_name, attack_path_name, step_name):
    url = f"{BASE_URL}/determine/command"
    
    payload = {"pentest_name": pentest_name, "attack_path_name": attack_path_name, "step_name": step_name}
    if allow_sniper_command_recommendations:
        payload["use_sniper"] = True

    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.json()['error']}")


def error_command(pentest_name, attack_path_name, step_name, error_output):
    url = f"{BASE_URL}/error/command"
    
    payload = {"pentest_name": pentest_name, "attack_path_name": attack_path_name, "step_name": step_name, "error_output": error_output}
    if allow_sniper_command_recommendations:
        payload["use_sniper"] = True
    
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.json()['error']}")


def provide_command_output(pentest_name, attack_path_name, step_name, command_output):
    # Define the endpoint
    endpoint = f'{BASE_URL}/provide/command_output'
    
    # Prepare the data payload
    data = {
        'pentest_name': pentest_name,
        'attack_path_name': attack_path_name,
        'step_name': step_name,
        'command_output': command_output
    }
    
    # Send the POST request
    try:
        response = requests.post(endpoint, json=data)
        if response.status_code == 200:
            return response.status_code, response.json()
        else:
            return response.status_code, response.json()
    except requests.exceptions.RequestException as e:
        return 'Error', str(e)


def provide_command_error(pentest_name, attack_path_name, step_name, error_output, notes=None):
    endpoint = f'{BASE_URL}/error/command'
    
    # Prepare the data payload
    data = {
        'pentest_name': pentest_name,
        'attack_path_name': attack_path_name,
        'step_name': step_name,
        'error_output': error_output
    }
    
    if notes != None:
        data["notes"] = notes
    
    # Send the POST request
    try:
        response = requests.post(endpoint, json=data)
        if response.status_code == 200:
            return response.status_code, response.json()
        else:
            return response.status_code, response.json()
    except requests.exceptions.RequestException as e:
        return 'Error', str(e)


def rethink_steps(pentest_name, attack_path_name, from_step_number, notes=None):
    url = f"{BASE_URL}/rethink/steps"
    payload = {
        "pentest_name": pentest_name,
        "attack_path_name": attack_path_name,
        "from_step_number": from_step_number
    }
    
    if allow_sniper_command_recommendations:
        payload["use_sniper"] = True
        
    if notes:
        payload["notes"] = notes
    
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.json()['error']}")


def determine_vulnerabilities(service, version, pentest_name=None, attack_path_name=None):
    url = f"{BASE_URL}/determine/vulns"
    payload = {
        "service": service,
        "version": version
    }
    if pentest_name:
        payload["pentest_name"] = pentest_name
    if attack_path_name:
        payload["attack_path_name"] = attack_path_name

    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    elif response.status_code == 404:
        print(f"Error: {response.json()['error']}")
    else:
        print(f"Error: Unexpected status code {response.status_code}")
    

def determine_instructions_for_repo_script(pentest_name, path_name, step_name):
    url = f"{BASE_URL}/determine/repo_instructions"
    payload = {
        "pentest_name": pentest_name,
        "path_name": path_name,
        "step_name": step_name
    }

    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    elif response.status_code == 404:
        print(f"Error: {response.json()['error']}")
    else:
        print(f"Error: Unexpected status code {response.status_code}")


def correct_service_name(pentest_name, path_name, service_name):
    url = f"{BASE_URL}/correct/service_name"
    payload = {
        "pentest_name": pentest_name,
        "path_name": path_name,
        "service_name": service_name
    }

    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    elif response.status_code == 404:
        print(f"Error: {response.json()['error']}")
    else:
        print(f"Error: Unexpected status code {response.status_code}")


def correct_version_number(pentest_name, path_name, version_number):
    url = f"{BASE_URL}/correct/version_number"
    payload = {
        "pentest_name": pentest_name,
        "path_name": path_name,
        "version_number": version_number
    }

    response = requests.post(url, json=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    elif response.status_code == 404:
        print(f"Error: {response.json()['error']}")
    else:
        print(f"Error: Unexpected status code {response.status_code}")