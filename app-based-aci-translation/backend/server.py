from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from copy import deepcopy
from werkzeug.utils import secure_filename
import subprocess, yaml, configparser, requests, os, zipfile, sys, glob, shutil

app = Flask(__name__)
CORS(app, support_credentials=True)

application_path = os.path.dirname(os.path.abspath(__file__))
ansible_to_TF_path = application_path + '/ansible_to_TF'

def extract_zip(input_zip):
    with zipfile.ZipFile(input_zip, 'r') as zip_ref:
        zip_ref.extractall(ansible_to_TF_path)
    return zip_ref.namelist()[0]

def remove_contents(folder):
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

def check_auth(host, username, password):
    session = requests.Session()
    session.verify = False
    login_url = "https://{0}/api/aaaLogin.json".format(host)
    login_payload = {
        "aaaUser": {
            "attributes": {
                "name": username,
                "pwd": password
            }
        }
    }
    response = session.post(login_url, json=login_payload)

    if response.ok:
        return True
    else: 
        return False

def include_task(original_content, playbook_from_zip=False):
    include_file = {
        'name': 'Include tasks to convert the play to TF config',
        'ansible.builtin.include_tasks': {
            'file': '{0}/ansible_to_TF.yml'.format(application_path)
        }
    }

    task_exists = any('tasks' in play for play in original_content)

    role_exists = any('roles' in play for play in original_content)
    
    if not task_exists and not role_exists and playbook_from_zip:
        original_content = [{'tasks': deepcopy(original_content)}]
    else:
        copy_original_content = deepcopy(original_content)
        copy_content_vars = deepcopy(original_content[0].get('vars', {}))
        copy_content_roles = deepcopy(original_content[0].get('roles', {}))
        copy_content_tasks = deepcopy(original_content[0].get('tasks', []))
        original_content = [{
            'name': 'aci_terraform',
            'hosts': 'aci',
            'gather_facts': False,
            'tasks': []
        }]
        if copy_content_vars:
            original_content[0]['vars'] = copy_content_vars
        if copy_content_roles:
            original_content[0]['roles'] = copy_content_roles
        if copy_content_tasks:
            original_content[0]['tasks'] = copy_content_tasks
        if not copy_content_tasks and not copy_content_roles and not copy_content_vars:
            original_content[0]['tasks'] = copy_original_content
    sections = ['tasks', 'pre_tasks', 'post_tasks', 'handlers', 'vars', 'vars_files', 'vars_prompt', 'imports', 'block', 'rescue']
    append_register_to_non_sections(original_content[0], sections, 0)
    if not task_exists and not role_exists and playbook_from_zip:
        return original_content[0]['tasks']
    else:
        original_content[0]['tasks'].append(include_file)
        return original_content

def append_register_to_non_sections(playbook, sections, counter):
    for section in sections:
        if section in playbook:
            if isinstance(playbook[section], list):
                for item in playbook[section]:
                    item.pop("delegate_to", None)
                    if [i for i in sections if i in item]:
                        append_register_to_non_sections(item, ['tasks'], counter)
                    else:
                        counter = counter + 1
                        if not any(key in item for key in ["include_tasks", "import_tasks", "vars", "ansible.builtin.include_tasks", "ansible.builtin.import_tasks", "ansible.builtin.vars"]):
                            if item.get("register") is None:
                                item["register"] = "content{0}".format(counter)
                            #item["ignore_errors"] = True
                        for key, val in item.items():
                            if isinstance(val, dict) and (("cisco.aci" in key) or ("aci_" in key)):
                                val.pop("host", None)
                                val.pop("hostname", None)
                                val.pop("username", None)
                                val.pop("user", None)
                                val.pop("password", None)
                                val.pop("validate_certs", None)
                                val.pop("use_proxy", None)
                                val["output_level"] = "debug"
                    append_register_to_non_sections(item, sections, counter)
            elif isinstance(playbook[section], dict):
                    counter = counter + 1
                    if not any(key in playbook[section] for key in ["include_tasks", "import_tasks", "vars", "ansible.builtin.include_tasks", "ansible.builtin.import_tasks", "ansible.builtin.vars"]):
                        if playbook[section].get("register") is None:
                            playbook[section]["register"] = "content{0}".format(counter)
                        #playbook[section]["ignore_errors"] = True
                    playbook[section].pop("delegate_to", None)
                    for key, parameter in playbook[section].items():
                        if isinstance(parameter, dict) and (("cisco.aci" in key) or ("aci_" in key)):
                            parameter.pop("host", None)
                            parameter.pop("hostname", None)
                            parameter.pop("username", None)
                            parameter.pop("user", None)
                            parameter.pop("password", None)
                            parameter.pop("validate_certs", None)
                            parameter.pop("use_proxy", None)
                            parameter["output_level"] = "debug"
                    append_register_to_non_sections(playbook[section], sections, counter)

def create_inventory(host, username, password):
    config = configparser.ConfigParser()
    if os.path.isfile('{0}/inventory.networking'.format(ansible_to_TF_path)):
        os.remove('{0}/inventory.networking'.format(ansible_to_TF_path))
    config.read('inventory.networking')
    config.add_section('aci')
    config.set('aci', 'ansible_to_TF ansible_host', host)
    config.add_section('aci:vars')
    config.set('aci:vars', 'ansible_user', username)
    config.set('aci:vars', 'ansible_password', password)
    config.set('aci:vars', 'ansible_network_os', 'cisco.aci.aci')
    config.set('aci:vars', 'ansible_connection', 'ansible.netcommon.httpapi')
    config.set('aci:vars', 'ansible_httpapi_use_ssl', 'True')
    config.set('aci:vars', 'ansible_httpapi_validate_certs', 'False')

    with open('{0}/inventory.networking'.format(ansible_to_TF_path), 'w') as configfile:
        config.write(configfile, space_around_delimiters=False)

def create_ansible_cfg(role_path):
    filter_plugin_dirs = [application_path + '/' + 'filter_plugins']
    lookup_plugin_dirs = []
    for root, dirs, files in os.walk(role_path):
        for dir in dirs:
            if 'filter' in dir:
                filter_plugin_dirs.append(os.path.join(root, dir))
            if 'lookup' in dir:
                lookup_plugin_dirs.append(os.path.join(root, dir))

    # build the filter_plugins path
    filter_plugins_path = ":".join(filter_plugin_dirs)
    lookup_plugins_path = ":".join(lookup_plugin_dirs)

    # create the configuration
    config = configparser.ConfigParser()
    config.read('ansible.cfg')

    if 'defaults' not in config.sections():
        config.add_section('defaults')

    config.set('defaults', 'roles_path', ansible_to_TF_path)
    config.set('defaults', 'filter_plugins', filter_plugins_path)
    config.set('defaults', 'lookup_plugins', lookup_plugins_path)

    # write the configuration to ansible.cfg
    with open(os.path.join(role_path, 'ansible.cfg'), 'w') as configfile:
        config.write(configfile)

@app.route('/translate', methods=['POST'])
def run_playbook():
    host = request.form.get('host')
    username = request.form.get('username')
    password = request.form.get('password')
    check_mode = request.form.get('isChecked') == 'true'  # Convert to boolean

    remove_contents(ansible_to_TF_path)

    # Check credentials
    if check_auth(host, username, password):
        create_inventory(host, username, password)
    else:
        return jsonify({'message': 'Invalid APIC Credentials'}, 401)

    for file in request.files.values():
        filename = secure_filename(file.filename)
        filepath = os.path.join(ansible_to_TF_path, filename)
        file.save(filepath)

        if zipfile.is_zipfile(file):
            playbook_dir = extract_zip(filepath)
            playbook_dir = playbook_dir.rstrip('/')
            original_playbook_path = ansible_to_TF_path + "/" + playbook_dir
            with open(ansible_to_TF_path + '/' + 'playbook_path.txt', 'w') as f:
                f.write(original_playbook_path)
            file_paths = []
            inventory_paths = []
            terraform_file_found = False
            yml_files = glob.glob(os.path.join(original_playbook_path, '*.yml')) + glob.glob(os.path.join(original_playbook_path, '*.yaml'))
            for root, dirs, files in os.walk(original_playbook_path):
                if 'tasks' in dirs:
                    file_paths.extend(glob.glob(os.path.join(root, 'tasks', '*.yml')))
                    file_paths.extend(glob.glob(os.path.join(root, 'tasks', '*.yaml')))
                for file in files:
                    if 'inventory' in file:
                        inventory_paths.append('-i' '{0}'.format(os.path.join(root, file)))
                    if 'terraform' in file or len(yml_files) == 1:
                        terraform_file_found = True
                        try:
                            file_to_open = os.path.join(root, file) if 'terraform' in file else yml_files[0]
                            with open(file_to_open, 'r') as play:
                                new_content = include_task(yaml.safe_load(play), True)
                            with open(os.path.join(original_playbook_path, 'aci-ansible.yml'), 'w') as playbook:
                                yaml.dump(new_content, playbook, width=float("inf"))
                        except Exception as e:
                            return jsonify({'message': 'Translator was unable to parse the playbook in the provided zip file.', 'error': str(e)}, 500)
            if not terraform_file_found and len(yml_files) == 0:
                return jsonify({'message': "Translator was unable to find 'terraform.yml'. Please re-name your playbook as 'terraform.yml'.", 'error': 'Playbook not found'}, 500)

            for file_path in file_paths:
                try:
                    with open(file_path, 'r+') as task:
                        new_content = include_task(yaml.safe_load(task), True)
                        task.seek(0)
                        yaml.dump(new_content, task, width=float("inf"))
                        task.truncate()

                except Exception as e:
                    return jsonify({'message': 'Translator was unable to parse the tasks in the role.', 'error': str(e)}, 500)    
            ansible_command = ['ansible-playbook', '{0}/aci-ansible.yml'.format(original_playbook_path), '-i' '{0}/inventory.networking'.format(ansible_to_TF_path), '-vvv']
            ansible_command.extend(inventory_paths)
        else:
            try:
                with open(filepath, 'r') as play:
                    new_content = include_task(yaml.safe_load(play), False)
                with open(os.path.join(ansible_to_TF_path, 'aci-ansible.yml'), 'w') as playbook:
                    yaml.dump(new_content, playbook, width=float("inf"))
            except Exception as e:
                return jsonify({'message': 'Translator was unable to parse the playbook.', 'error': str(e)}, 500)
            original_playbook_path = ansible_to_TF_path
            with open(ansible_to_TF_path + '/' + 'playbook_path.txt', 'w') as f:
                f.write(original_playbook_path)
            ansible_command = ['ansible-playbook', '{0}/aci-ansible.yml'.format(original_playbook_path), '-i' '{0}/inventory.networking'.format(ansible_to_TF_path), '-vvv']
        create_ansible_cfg(original_playbook_path)
    if check_mode:
        ansible_command.append('--check')
    try:
        try:
            f = open('{0}/logfile.log'.format(original_playbook_path), 'w')
            logfile = True
        except Exception as e:
            logfile = False
        ansible_process = subprocess.Popen(ansible_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=original_playbook_path)
        while True:
            output = ansible_process.stdout.readline().decode('utf-8')
            if output == '' and ansible_process.poll() is not None:
                break
            if output:
                if logfile:
                    print(output.strip(), file=f)
                print(output.strip())

        rc = ansible_process.poll()

        ansible_warnings = ansible_process.stderr.read().decode('utf-8')
        if rc != 0:
            return jsonify({'message': 'Error executing translation', 'error': 'Non-zero return code from Ansible'}, 500)
        elif ansible_warnings != "":
            if logfile:
                print(ansible_warnings, file=f)
            return jsonify({'message': 'Translation executed successfully with exceptions. Please check the logfile for more details and use the Terraform files with caution.'}, 200)
        else:
            return jsonify({'message': 'Translation executed successfully'}, 200)
    except Exception as e:
        return jsonify({'message': 'Error executing translation', 'error': str(e)}, 500)
    finally:
        if logfile:
            f.close()

@app.route('/download-terraform-files', methods=['GET'])
def download_files():
    with open(ansible_to_TF_path + '/' + 'playbook_path.txt', 'r') as f:
        original_playbook_path = f.read()
    terraform_config = '{0}/aci_terraform/resources.tf'.format(original_playbook_path)
    terraform_state = '{0}/aci_terraform/terraform.tfstate'.format(original_playbook_path)
    terraform_provider = '{0}/aci_terraform/provider.tf'.format(original_playbook_path)
    terraform_logs = '{0}/logfile.log'.format(original_playbook_path)
    terraform_templates_path = '{0}/aci_terraform/terraform_templates'.format(original_playbook_path)
    zip_filename = '{0}/terraform_files.zip'.format(original_playbook_path)
    with zipfile.ZipFile(zip_filename, 'w') as zip_file:
        zip_file.write(terraform_config, 'resources.tf')
        zip_file.write(terraform_state, 'terraform.tfstate')
        zip_file.write(terraform_provider, 'provider.tf')
        if os.path.exists(terraform_logs):
            zip_file.write(terraform_logs, 'logfile.log')
        if os.path.exists(terraform_templates_path):
            for filename in os.listdir(terraform_templates_path):
                if filename != 'generate_templates.go':
                    zip_file.write(terraform_templates_path + '/' + filename, 'terraform_templates/' + filename)

    return send_file(zip_filename)

if __name__ == '__main__':
    app.run(port=5000, debug=False)