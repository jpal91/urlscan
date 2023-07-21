
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
        target = self.validate_url(url, both=True)

        if isinstance(target, list):
            return self.get_json_reports(target)
        
        return self.get_json_report(target)

    def get_report(self, target: Union[str, list], prev_report: Optional[str] = None) -> str:
        """
        Generates the URLHaus report for a given url or list of urls.

        Args:
            target (Union[str, list]): The url or list of urls to scan.

        Returns:
            (str): The URLHaus report.
        """

        if isinstance(target, str):
            report = self._get_report_str(target)
        else:
            report = self.get_json_reports(target)
        
        if report:
            self.urgent = True

        report = self.finalize_report(self.gen_print_report(report, ''), 'URLHaus')

        if prev_report:
            # if self.urgent:
            #     return prev_report + report
            # else:
                return self.mark_urgent(prev_report + report)

        return self.mark_urgent(report)