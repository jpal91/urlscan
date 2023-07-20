
import base64
import requests
from src import Printer

class VirusTotal(Printer):

    def __init__(self, url: str, api_key: str):
        super().__init__()
        self.url = url
        self.headers = {
            'x-apikey': api_key,
            'accept': 'application/json'
        }

    def encode_base64(self, url: str) -> str:
        """
        Per VirusTotal API documentation, the url must be base64 encoded 
            and stripped of trailing '=' characters.
        """
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def get_json_report(self, raw_url: str) -> str:
        """
        Generates raw VirusTotal report for a given url.

        Args:
            raw_url (str): The url to scan.

        Returns:
            (dict or None): The raw VirusTotal report or None if the url is not found.
        """

        url = self.encode_base64(raw_url)

        res = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url}",
            headers=self.headers,
            timeout=30
        )

        if res.status_code != 200:
            return None

        return res.json()['data']['attributes']

    def get_vt_report(self) -> str:
        """
        Generates the VirusTotal report for the url and checks it for malicious keywords.
        It will first get the JSON report, remove some unnecessary fields, 
            then generate the report string.

        Returns:
            (str): The VirusTotal report that can be printable to the console.
        """

        report = self.get_json_report(self.url)
        if not report:
            return self.finalize_report(None, 'VirusTotal')

        del_list = [
            "last_analysis_results",
            "last_http_response_headers",
            "last_http_response_content_sha256",
            "last_http_response_content_length",
            "tld",
            "html_meta",
            "last_http_response_code",
        ]

        for d_item in del_list:
            if d_item in report:
                del report[d_item]

        # An extra step to make sure the urls are at the top of the printed report.
        url, final_url = report["url"], report["last_final_url"]
        new_report = {"original_url": url, "final_url": final_url, **report}
        del new_report["url"]
        del new_report["last_final_url"]

        # Sets the url to the final url returned by the report. Good for redirects.
        # Since the URLHaus report is called after this report,
        #   it makes the following report more accurate.
        self.url = final_url

        printed_report = self.gen_print_report(new_report, "")

        checked_report = self._check_report(printed_report)

        return checked_report
