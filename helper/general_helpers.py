import json

def json_extractor(response):
    # Strip the leading and trailing triple quotes and `json` annotation
    json_string = response.strip('`json \n')
    # Parse the JSON string into a Python dictionary
    try:
        return json.loads(json_string)
    except:
        return None


def write_json(data, filename):
    """
    Writes a dictionary to a JSON file.
    
    :param data: Dictionary to write.
    :param filename: Name of the file to write the JSON data to.
    """
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)


def read_json(filename):
    """
    Reads a JSON file and returns the data as a dictionary.
    
    :param filename: Name of the file to read the JSON data from.
    :return: A dictionary with the data read from the JSON file.
    """
    with open(filename, 'r') as file:
        return json.load(file)
