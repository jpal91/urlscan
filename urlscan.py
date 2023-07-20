import sys
import os
from datetime import datetime
import base64
import requests
from dotenv import load_dotenv
load_dotenv()

class URLInfo:
    def __init__(self, url, api_key=None):
        self.url = url
        self.report = None
        self.urgent = None
        self.api_key = api_key
        self.vt_headers = {
            "x-apikey": api_key,
            "accept": "application/json",
        }

    def encode_base64(self, url: str):
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _get_vt_report(self, raw_url):
        url = self.encode_base64(raw_url)

        res = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url}", headers=self.vt_headers
        )
        
        if res.status_code == 404:
            return None
        
        return res.json()["data"]["attributes"]

    def _check_report(self, report):
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

        report_string = f"\n\033[1mVirusTotal Report:\033[0m\n{report}\n"

        return report_string

    def get_vt_report(self, full=False):
        self.report = self._get_vt_report(self.url)
        if not self.report:
            return self._check_report(None)
        
        del_list = [
            "last_analysis_results",
            "last_http_response_headers",
            "last_http_response_content_sha256",
            "last_http_response_content_length",
            'tld',
            'html_meta',
            'last_http_response_code'
        ]
        
        for d in del_list:
            if d in self.report:
                del self.report[d]

        if not full:
            new_report = {
                "url": self.report["url"],
                "final_url": self.report["last_final_url"],
                "total_votes": self.report["total_votes"],
                "stats": self.report["last_analysis_stats"],
                "reputation": self.report["reputation"],
            }

            if "redirection_chain" in self.report:
                new_report["redirection_chain"] = self.report["redirection_chain"]

            printed_report = self.gen_report(new_report, "")

        else:
            url, final_url = self.report["url"], self.report["last_final_url"]
            new_report = {
                'original_url': url,
                'final_url': final_url,
                **self.report
            }
            del new_report['url']
            del new_report['last_final_url']
            self.url = final_url
            
            printed_report = self.gen_report(new_report, "")

        checked_report = self._check_report(printed_report)

        return checked_report
    
    def _check_url_and_print(func):
        def wrapper(self, url):
            if not url.startswith("http") or not url.startswith("https"):
                res = func(self, 'http://' + url) or func(self, 'https://' + url)
            else:
                res = func(self, url)
            
            printed_report = self.gen_report(res, "")
            report_string = f"\n\033[1mURLHaus Report:\033[0m\n{printed_report}\n"
            return report_string
        return wrapper

    @_check_url_and_print
    def get_urlhaus_report(self, url):
        res = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            headers={"Accept": "application/json"},
            data={"url": url},
        )

        res = res.json()

        if res["query_status"] == "ok":
            self.urgent = True
            return res
        else:
            return None

    
    def get_reports(self, vt=True, uh=True):
        reports = ''
        if vt and self.api_key:
            reports += self.get_vt_report()
        if uh:
            reports += self.get_urlhaus_report(self.url)
        
        if self.urgent:
            reports = (
                "\n\033[41;1mWARNING: Malicious content detected!\033[0m\n"
                + reports
            )
        return reports

    def _get_timestamp(self, num):
        return datetime.fromtimestamp(num).strftime("%Y-%m-%d %H:%M:%S")

    def gen_report(self, report, string, title=None, tabs=0):
        tab_str = "\t" * tabs

        if type(report) is dict:
            string += f"\n{title}:" if title else ""
            for key, value in report.items():


                title_str = key.replace("_", " ").capitalize()
                if not value and value != 0:
                    string += f"\n{tab_str}{title_str}: null"
                elif type(value) is int and 'date' in key:
                    string += f"\n{tab_str}{title_str}: {self._get_timestamp(value)}"
                elif type(value) is str or type(value) is int:
                    string += f"\n{tab_str}{title_str}: {value}"
                else:
                    string = self.gen_report(value, string, title_str, tabs + 1)
        elif type(report) is list:
            string += f"\n{title}:" if title else ""
            for item in report:
                if type(item) is str:
                    next_str = string + "\n"
                else:
                    next_str = string
                string = self.gen_report(item, next_str, tabs=tabs)
        else:
            string += f"{tab_str}{report}"

        return string


if __name__ == "__main__":
    if len(sys.argv) < 2:
        exit('Please provide a URL to scan.')

    api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    
    res = URLInfo(sys.argv[1], api_key).get_reports()
    print(res)
    