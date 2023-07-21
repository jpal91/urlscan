import sys
import os
import time
import threading
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
    
    # print(report)
    return report

class MainThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.report = None
    
    def run(self):
        self.report = main()

class WaitingThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.done = False
    
    def run(self):

        while not self.done:
            for i in range(1, 4):
                print('  Scanning' + '.' * i, end='\r')
                time.sleep(0.5)
            print(' ' * 14, end='\r')

if __name__ == '__main__':
    # main()
    main_thread = MainThread()
    waiting_thread = WaitingThread()

    waiting_thread.start()
    main_thread.start()

    main_thread.join()

    waiting_thread.done = True

    waiting_thread.join()
    print(main_thread.report)
    