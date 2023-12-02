import argparse
import json
import os
import requests
import subprocess
import yaml
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

token = os.getenv('SEMGREP_APP_TOKEN')
# Look for the .semgrep/settings.yml where we keep login tokens if no ENV var
if token is None:
    try:
        semgrep_settings = open(Path.home() / ".semgrep" / "settings.yml", "r")
        lines = semgrep_settings.readlines()
        # the line we want starts with api_token
        token_line = [line.rstrip() for line in lines if line.startswith("api_token")].pop()
        _, token = token_line.split(': ')
        semgrep_settings.close() 
    except FileNotFoundError:
        print("No Semgrep settings found")

if token is None:
    print("No token found - set SEMGREP_APP_TOKEN or use `semgrep login` before running.")
    exit()

def get_deployment_rules(query_params, filename):
    base_url = "https://semgrep.dev/api/agent/deployments/scans/config"
    headers = {
        'Authorization': f'Bearer {token}',
        'User-Agent': 'Semgrep/1.46.0'
    }
    
    url_params = urlencode(query_params)
    path = f"{base_url}?{url_params}"

    response = requests.get(path, headers=headers)
    response.raise_for_status()
    
    data = response.json()
    
    with open(filename, 'w') as outfile:
        json.dump(json.loads(data['rule_config']), outfile)

def get_rule(id):
    registry_url = "https://semgrep.dev/api/registry/rules/"
    path = f"{registry_url}/{id}"
    response = requests.get(path)
    response.raise_for_status()
    return response.json()
    
def extract_custom_rules(filename):
    with open(filename, 'r') as rule_file:
        rules = json.load(rule_file)        
        custom_rules = [rule for rule in rules['rules']
                            if "semgrep.dev" in rule['metadata'].keys() 
                            and rule['metadata']["semgrep.dev"]['rule']['origin'] == "custom"]
        # print(custom_rules)
        return custom_rules

def compare_with_original(rules, date=None):
    for rule in rules:
        rule_metadata = rule['metadata']
        # print(rule_metadata)
        # If this is not present, the rule is fully custom and doesn't need to be checked
        if rule_metadata.get('original-rule'):
            original_rule_id = rule_metadata['original-rule']
            original_rule = get_rule(original_rule_id)
            # print(original_rule)
            last_change_at = datetime.strptime(original_rule['last_change_at'], "%a, %d %b %Y %H:%M:%S %Z")
            # Check the original rule's last changed time
            if date and last_change_at < date:
                # If a date was provided and change date is less than supplied date, rule has not been updated recently
                pass
            else:
                # A date was not provided, or the rule was updated more recently than the supplied date
                original_pattern = extract_patterns(original_rule)
                current_pattern = extract_patterns(rule)
                
                original_yaml = yaml.dump(original_pattern)
                current_yaml = yaml.dump(current_pattern)

                # This inequality is naive rather than semantic, but diffing the result helps to keep the output manageable
                if original_pattern != current_pattern:
                    with(open(rule['id'], 'w') as custom_rule_file, open(original_rule_id, 'w') as original_rule_file):
                        yaml.dump(original_pattern, original_rule_file)
                        yaml.dump(current_pattern, custom_rule_file)
                        diff_result = subprocess.run(["diff", "-U", "0", "-b", rule['id'], original_rule_id], capture_output=True)
                        print(f'''Rule ID: {rule['id']}
{diff_result.stdout.decode()}''')

def extract_patterns(rule):
    patterns = []
    # Registry rules
    if rule.get('definition'):
        definition = rule['definition']['rules'][0]
        patterns = [{key: definition[key]} for key in definition.keys() if key.startswith('pattern')]
    # Custom rules
    else:
        patterns = [{key: rule[key]} for key in rule.keys() if key.startswith('pattern')]

    return patterns

if __name__ == "__main__":
    # Parse CLI args
    parser = argparse.ArgumentParser(
                        prog='track-rule-updates',
                        description='Compares custom rules in a Semgrep deployment config with corresponding registry rules')
    parser.add_argument("--date", help='Date (in ISO8601 format) to compare against', required=False)
    args = parser.parse_args()
    if args.date:
        date = datetime.strptime(args.date, '%Y-%m-%d')
    else:
        date = None
    
    try:
        # get_deployment_rules({
        #     'sca': 'False',
        #     'full_scan': 'True'
        # }, "sast.json")
        rules = extract_custom_rules("sast.json")
        compare_with_original(rules, date)
    except requests.exceptions.RequestException as e:
        # Handle exceptions from requests
        print(f"An HTTP error occurred: {e}")
    except Exception as e:
        # Handle other possible exceptions
        print(f"An error occurred: {e}")