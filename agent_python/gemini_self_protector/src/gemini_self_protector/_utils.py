import re
import base64
import html
import urllib.parse
import requests


class _Utils(object):

    def decoder(string):
        """Decode a string using the specified encoding type."""

        # Remove the invalid escape sequences  - # Remove the backslash
        string = string.replace('\%', '%').replace(
            '\\', '').replace('<br/>', '')

        string = string.encode().decode('unicode_escape')

        string = urllib.parse.unquote(string)

        string = html.unescape(string)

        # Use a regular expression to find all base64-encoded segments in the string
        base64_pattern = r'( |,|;)base64,([A-Za-z0-9+/]*={0,2})'

        # Iterate over the matches and decode the base64-encoded data
        match = re.search(base64_pattern, string)
        if match:
            encoded_string = match.group(2)

            # Try first base64-decode
            try:
                decoded_string = base64.b64decode(encoded_string).decode()
                string = string.replace(encoded_string, decoded_string)
            except:
                pass

            # Try second base64-decode
            try:
                string = string.replace('\%', '%').replace(
                    '\\', '').replace('<br/>', '').replace(' ', '')
                match = re.search(base64_pattern, string)

                if match:
                    encoded_string = match.group(2)
                    try:
                        decoded_string = base64.b64decode(
                            encoded_string).decode()
                        string = string.replace(encoded_string, decoded_string)
                    except:
                        pass
            except:
                pass

        # Use a regular expression to find all url end with .js
        url_pattern = r'(?:https?://|//).+\.js'

        matches = re.findall(url_pattern, string)

        if matches:
            for match in matches:
                # alert('noobpk') - 5dc6f09bb9f90381814ff9fcbfe0a685
                string = string.replace(
                    match, ' 5dc6f09bb9f90381814ff9fcbfe0a685')

        # Lowercase string
        string = string.lower()

        # Use a regular expression to find all query
        sql_pattern = r'(select.+)|(select.+(?:from|where|and).+)|(exec.+)'

        match = re.search(sql_pattern, string)

        if match:
            # select * from noobpk; - 90e87fc8ba835e0d2bfeec5e3799ecfe
            string = string.replace(
                match[0], ' 90e87fc8ba835e0d2bfeec5e3799ecfe')

        string = string.encode('utf-7').decode()

        string = string.encode('utf-7').decode()

        # Lowercase string
        string = string.lower()

        return string

    def web_vuln_detect_predict(payload):
        headers = {"Content-Type": "application/json"}
        predict = requests.post(
            'https://web-vuln-detection.hptcybersec.com/predict', json={"data": payload}, headers=headers)
        response = predict.json()
        accuracy = response.get('accuracy')
        return accuracy
