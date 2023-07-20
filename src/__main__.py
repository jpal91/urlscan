import sys
import os
from dotenv import load_dotenv
from src import URLInfo
load_dotenv()

def main():
    if len(sys.argv) < 2:
        exit("Please provide a URL to scan.")

    api_key = os.environ.get("VIRUSTOTAL_API_KEY")

    res = URLInfo(sys.argv[1], api_key).get_reports()
    print(res)

if __name__ == '__main__':
    main()