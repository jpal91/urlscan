"""BaseReport class"""
from urllib.parse import urlparse
from typing import Union
from datetime import datetime
from typing import Union, Optional

class BaseReport:
    """Base class for other report classes"""

    def __init__(self):
        self.urgent = False

    def validate_url(self, url: str, both: bool = False) -> Union[list, str]:
        """Validates the url and returns the domain"""
        parsed_url = urlparse(url)
        
        if parsed_url.scheme in ["http", "https"]:
            return url

        if not parsed_url.scheme:
            if both:
                return [f"http://{url}", f"https://{url}"]
            return "http://" + url
        else:
            raise ValueError("Invalid url")
        
    def get_timestamp(self, time_int: int) -> str:
        """
        VirusTotal returns timestamps as unix timestamps. Helper function to convert.
        """
        return datetime.fromtimestamp(time_int).strftime("%Y-%m-%d %H:%M:%S")

    def mark_urgent(self, report: str) -> str:
        """Adds a warning to the given report str"""
        if not self.urgent:
            return report

        return "\n\033[41;1mWARNING: Malicious content detected!\033[0m\n" + report

    def finalize_report(self, report: str, name: str) -> str:
        """Caps report off with a title"""
        return f"\n\033[94;1m{name} Report:\033[0m\n{report}\n"

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
                    string += f"\n{tab_str}{title_str}: {self.get_timestamp(value)}"

                elif isinstance(value, (str, int)):
                    string += f"\n{tab_str}{title_str}: {value}"

                # Handles nested dicts and lists and adds one tab to the string
                # If nested dict, adds the current tab string to title as well
                #   to keep the title on the same level as the nested items.
                elif isinstance(value, dict):
                    string = self.gen_print_report(value, string, tab_str + title_str, tabs + 1)
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
