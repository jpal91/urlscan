"""URLInfo Class"""
import sys
import os
from datetime import datetime
import base64
from typing import Union, Optional
import requests
from dotenv import load_dotenv

load_dotenv()


class URLInfo:
    """
    Takes a url and allows the generation of reports from VirusTotal 
        and URLHaus indicating whether or not the url is malicious.
    """

    def __init__(self, url: str, api_key: Optional[str] = None) -> None:
        """
        Takes a url and allows the generation of reports from VirusTotal 
            and URLHaus indicating whether or not the url is malicious.
        
        Args:
            url (str): The url to scan.
            api_key (str, optional): The VirusTotal API key. Defaults to None. 
                If None, VirusTotal reports will not be generated.
        """

        self.url = url
        self.urgent = None
        self.api_key = api_key

    def _encode_base64(self, url: str) -> str:
        """
        Per VirusTotal API documentation, the url must be base64 encoded 
            and stripped of trailing '=' characters.
        """
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def get_json_vt_report(self, raw_url: str) -> Optional[dict]:
        """
        Generates raw VirusTotal report for a given url.

        Args:
            raw_url (str): The url to scan.

        Returns:
            (dict or None): The raw VirusTotal report or None if the url is not found.
        """

        if not self.api_key:
            raise Exception("No VirusTotal API key provided.")

        url = self._encode_base64(raw_url)

        headers = {
            "x-apikey": self.api_key,
            "accept": "application/json",
        }

        res = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url}", 
            headers=headers,
            timeout=30
        )

        # TODO: Error handling
        if res.status_code != 200:
            return None

        return res.json()["data"]["attributes"]

    def _check_report(self, report: Optional[str]) -> str:
        """
        Helper function that checks the report str for any malicious keywords 
            and highlights them in red.
        """

        bad_words = ["malware", "severity", "infection"]

        if report:
            for word in bad_words:
                if word in report:
                    report = report.replace(word, f"\033[31;1m{word}\033[0m")
                    self.urgent = True
                elif word.capitalize() in report:
                    report = report.replace(
                        word.capitalize(), f"\033[31;1m{word.capitalize()}\033[0m"
                    )
                    self.urgent = True

        report_string = f"\n\033[94;1mVirusTotal Report:\033[0m\n{report}\n"

        return report_string

    def get_vt_report(self) -> str:
        """
        Generates the VirusTotal report for the url and checks it for malicious keywords.
        It will first get the JSON report, remove some unnecessary fields, 
            then generate the report string.

        Returns:
            (str): The VirusTotal report that can be printable to the console.
        """

        report = self.get_json_vt_report(self.url)
        if not report:
            return self._check_report(None)

        del_list = [
            "last_analysis_results",
            "last_http_response_headers",
            "last_http_response_content_sha256",
            "last_http_response_content_length",
            "tld",
            "html_meta",
            "last_http_response_code",
        ]

        for d in del_list:
            if d in report:
                del report[d]

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

    # TODO: Refactor to urlparse
    def _check_url_and_print(func: callable) -> callable:
        """
        Wrapper function that takes an instance of get_urlhaus_report 
            and checks the url for http or https.
        If http or https are not present, it attempts to run the function with both prepended 
            to the url and returns the result formatted for printing.
        """

        def wrapper(self, url: str) -> str:
            if not url.startswith("http") or not url.startswith("https"):
                res = func(self, "https://" + url) or func(self, "http://" + url)
            else:
                res = func(self, url)

            printed_report = self.gen_print_report(res, "")
            report_string = f"\n\033[94;1mURLHaus Report:\033[0m\n{printed_report}\n"
            return report_string

        return wrapper


    @_check_url_and_print
    def get_urlhaus_report(self, url: str) -> Optional[dict]:
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
        )

        res = res.json()

        if res["query_status"] == "ok":
            self.urgent = True
            return res
        else:
            return None

    def get_reports(self, virus_total: bool = True, u_haus: bool = True) -> str:
        """
        Attempts to generate reports for VirusTotal and/or URLHaus.
        If during the genration of either report, malicious content is detected, 
            the urgent flag is set to True.
        This flag is used to indicate to the user that the url is malicious 
            and will add an extra warning to the report.

        Args:
            virus_total (bool, optional): Whether or not to generate a VirusTotal report.
                Defaults to True.
            u_haus (bool, optional): Whether or not to generate a URLHaus report. Defaults to True.

        Returns:
            (str): The reports that can be printable to the console.
        """

        reports = ""

        if virus_total and self.api_key:
            reports += self.get_vt_report()

        if u_haus:
            reports += self.get_urlhaus_report(self.url)

        if self.urgent:
            reports = (
                "\n\033[41;1mWARNING: Malicious content detected!\033[0m\n" + reports
            )

        return reports

    def _get_timestamp(self, num: int) -> str:
        """
        VirusTotal returns timestamps as unix timestamps. Helper function to convert.
        """
        return datetime.fromtimestamp(num).strftime("%Y-%m-%d %H:%M:%S")

    def gen_print_report(
        self,
        report: Union[dict, list, str, None],
        string: str,
        title: Optional[str] = None,
        tabs: int = 0,
    ) -> str:
        """
        Recursive function to generate the printable report string.
        The initial report will always be a dict.
            Any nested items are handled depending on the type.
        Generally when a nested item is a dict or list, it will be prepended with a tab.

        Args:
            report (Union[dict, list, str, None]): The report to generate.
            string (str): The current report string.
            title (str, optional): The title of the section. 
                Generally used if a dict or list has nested items which will have an extra tab over. 
                Defaults to None.
            tabs (int, optional): The number of tabs to prepend to the string. Defaults to 0.
        
        Returns:
            (str): The report string.
        """

        # Creates tab string based on the number of tabs the function was called with 
        #   to prepend to the string based on level of nesting.
        tab_str = "\t" * tabs

        if isinstance(report, dict):
            string += f"\n{title}:" if title else ""

            for key, value in report.items():
                title_str = key.replace("_", " ").capitalize()

                # Handles empty dicts, lists, and None values
                if not value and value != 0:
                    string += f"\n{tab_str}{title_str}: null"

                # Handles unix timestamps, more specifically for VirusTotal reports
                elif isinstance(value, int) and "date" in key:
                    string += f"\n{tab_str}{title_str}: {self._get_timestamp(value)}"

                elif isinstance(value, (str, int)):
                    string += f"\n{tab_str}{title_str}: {value}"

                # Handles nested dicts and lists and adds one tab to the string
                else:
                    string = self.gen_print_report(value, string, title_str, tabs + 1)

        elif isinstance(report, list):
            string += f"\n{title}:" if title else ""

            for item in report:
                # Adds an extra line break specifically if the item is a string.
                # Nested dicts or lists will have their own line break added by the recursive call.
                if isinstance(item, str):
                    next_str = string + "\n"
                else:
                    next_str = string

                string = self.gen_print_report(item, next_str, tabs=tabs)

        # Handles strings and None values
        else:
            string += f"{tab_str}{report}"

        return string


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Please provide a URL to scan.")

    url_report = URLInfo(
        sys.argv[1],
        os.environ.get("VIRUSTOTAL_API_KEY"),
    ).get_reports()

    print(url_report)
