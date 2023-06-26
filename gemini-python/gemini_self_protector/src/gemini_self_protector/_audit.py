from ._config import _Config
import os
import requests
import time


class _Audit(object):

    def __find_requirements_file__() -> None:
        running_directory = os.getcwd()
        results = []
        for root, dirs, files in os.walk(".", topdown=True):
            if root[len(running_directory):].count(os.sep) <= 2:
                for file in files:
                    if file == "requirements.txt":
                        results.append(os.path.join(root, file))

        for root, dirs, files in os.walk("../", topdown=True):
            for file in files:
                if file == "requirements.txt":
                    results.append(os.path.join(root, file))
        return results

    def __dependency_vulnerability__(file_path):
        with open(file_path, 'r') as file:
            packages = [line.strip() for line in file]

        audit_result = []
        for package in packages:
            # split the package name and version
            name, version = package.split('==')
            print(f'Package name: {name}, Version: {version}')

            # Search for CVEs in NVD database
            url = f'https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={name}+{version}'
            response = requests.get(url)
            data = response.json()
            # If there are any CVEs, print out the relevant information
            if data['totalResults'] > 0:
                for result in data['result']['CVE_Items']:
                    cve_id = result['cve']['CVE_data_meta']['ID']
                    severity = result['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                    _Config.store_tb_dependency(name, version, cve_id, severity)
            else:
                _Config.store_tb_dependency(name, version, 'N/A', 'N/A')
            time.sleep(7)

        
