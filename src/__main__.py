import sys
import os
from dotenv import load_dotenv
from src import VirusTotal, URLHaus
load_dotenv()

def get_urls(report: dict) -> list:
    return [
        report["url"],
        report["last_final_url"],
        *report["redirection_chain"],
    ]

def main():
    if len(sys.argv) < 2:
        exit("Please provide a URL to scan.")

    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    v_total, v_report, urls = None, None, None

    if api_key:
        v_total = VirusTotal(sys.argv[1], api_key)
        v_report = v_total.get_report()

    u_haus = URLHaus()

    if v_total.report:
        urls = get_urls(v_total.report)
        report = u_haus.get_report(urls, v_report)
    else:
        report = u_haus.get_report(sys.argv[1])
    
    print(report)

if __name__ == '__main__':
    main()
    