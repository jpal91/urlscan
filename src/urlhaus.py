
import requests
from typing import Optional, Union
from src import BaseReport

class URLHaus(BaseReport):

    def __init__(self):
        super().__init__()

    def get_json_report(self, url: str) -> Optional[dict]:
        """
        Runs the url through URLHaus to check if it is malicious.

        Args:
            url (str): The url to scan.

        Returns:
            (dict or None): The URLHaus report or None if the url is not found.
        """

        res = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            headers={"Accept": "application/json"},
            data={"url": url},
            timeout=30
        ).json()

        if res["query_status"] != "ok":
            return None
        
        self.urgent = True
        return res
    
    def get_json_reports(self, urls: list) -> Optional[dict]:
        """
        Runs the urls through URLHaus to check if they are malicious.
        Breaks if a url is found to be malicious or no results are found.

        Args:
            urls (list): The urls to scan.

        Returns:
            (dict or None): The URLHaus report or None if the url is not found.
        """

        while True:
            for url in urls:
                res = self.get_json_report(url)
                if res:
                    return res 
            break
    
    def _get_report_str(self, url: str) -> Optional[dict]:
        """
        Validates the url and returns the URLHaus report for the url.

        Args:
            url (str): The url to scan.
        
        Returns:
            (dict or None): The URLHaus report or None if the url is not found.
        """
        target = self.validate_url(url, both=True)

        # validate_url could return a list of urls if the url doesn't have a scheme
        #  and both=True. If this is the case, we want to scan both urls.
        #  ie google.com -> ["http://google.com", "https://google.com"]
        if isinstance(target, list):
            return self.get_json_reports(target)
        
        return self.get_json_report(target)

    def get_report(self, target: Union[str, list], prev_report: Optional[str] = None) -> str:
        """
        Generates the URLHaus report for a given url or list of urls.
        When a VirusTotal report is generated alongside this report,
            there could be multiple URLs to scan, especially if there are redirects.

        Args:
            target (Union[str, list]): The url or list of urls to scan.
            prev_report (Optional[str], optional): The VirusTotal report. Defaults to None.

        Returns:
            (str): The URLHaus (or VirusTotal + URLHaus, if applicable) report.
        """

        if isinstance(target, str):
            report = self._get_report_str(target)
        else:
            report = self.get_json_reports(target)
        
        if report:
            self.urgent = True

        report = self.finalize_report(self.gen_print_report(report, ''), 'URLHaus')

        if prev_report:
            return self.mark_urgent(prev_report + report)

        return self.mark_urgent(report)