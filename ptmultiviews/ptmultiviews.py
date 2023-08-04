#!/usr/bin/python3
"""
    Copyright (c) 2023 Penterep Security s.r.o.

    ptmultiviews - Apache Multiviews detection & enumeration tool

    ptmultiviews is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptmultiviews is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptmultiviews.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import copy
import re
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import typing
import urllib

import requests
import validators

from _version import __version__
from ptlibs import ptjsonlib, ptmisclib, ptnethelper, ptprinthelper, ptpathtypedetector
from ptlibs.threads import ptthreads


class PtMultiviews:
    def __init__(self, args):
        self.ptjsonlib            = ptjsonlib.PtJsonLib()
        self.ptthreads            = ptthreads.PtThreads()
        self.ptpathtypedetector   = ptpathtypedetector.PtPathTypeDetector()
        self.without_domain       = args.without_domain
        self.use_json             = args.json
        self.with_requested_url   = args.with_requested_url
        self.cache                = args.cache
        self.path_list            = []

        # Test type
        self.url_test             = None # only url
        self.file_test            = None # only file
        self.domain_file_test     = None # domain + file combo

        # Requests args
        self.output_file          = self._get_output_file(args.output) if args.output else None
        self.headers              = ptnethelper.get_request_headers(args)
        self.timeout              = args.timeout
        self.redirects            = args.redirects
        self.proxies              = {"http": args.proxy, "https": args.proxy}

    def run(self, args):
        """Main method"""
        self.url_list             = self._get_urls(args.url, args.domain, args.file)
        self.original_url_list    = copy.copy(self.url_list)

        if self.url_test:
            if self._is_vulnerable(self.url_list[0]) and not args.check_only:
                ptprinthelper.ptprint("Enumerated:", "TITLE", not self.use_json, newline_above=True, colortext=True)
                self.ptthreads.threads(self.url_list, self._enumerate_files, 1)

        elif self.domain_file_test:
                ptprinthelper.ptprint("Enumerated:", "TITLE", not self.use_json, newline_above=True, colortext=True)
                self.ptthreads.threads(self.url_list, self._enumerate_files, args.threads)

        elif self.file_test:
            ptprinthelper.ptprint("Enumerated:", "TITLE", not self.use_json, newline_above=True, colortext=True)
            self.ptthreads.threads(self.url_list, self._enumerate_files, args.threads)

        ptprinthelper.ptprint('\n'.join(sorted(self.path_list)), "", not self.use_json)

        if self.output_file:
            if self.path_list:
                self.output_file.write('\n'.join(self.path_list))
                self.output_file.write('\n')
                ptprinthelper.ptprint(f"Output saved successfully to: {args.output}", "", not self.use_json, newline_above=True)
            self.output_file.close()

        ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), condition=self.use_json)

    def _is_vulnerable(self, url: str) -> bool:
        """Checks whether <url> is vulnerable to multiviews"""
        STATUS_CODES = [200, 301, 302]
        malformed_url = self._strip_url_extension(url)
        try:
            response, response_dump = ptmisclib.load_url_from_web_or_temp(url=malformed_url, method="GET", headers=self.headers, proxies=self.proxies, timeout=self.timeout, redirects=self.redirects, verify=False, cache=self.cache, dump_response=True)
        except requests.exceptions.RequestException as e:
            self.ptjsonlib.end_error(f"Cannot connect to website: {e}", self.use_json)

        ptprinthelper.ptprint(f"Testing URL: {response.url}", "INFO", not self.use_json)
        ptprinthelper.ptprint(f"Status code: {response.status_code}", "INFO", not self.use_json)

        # Checks whether multiviews enabled
        if response.status_code in STATUS_CODES and response.headers.get("Vary") and "negotiate" in response.headers.get("Vary"):
            ptprinthelper.ptprint(f"Multiviews: Enabled", "VULN", not self.use_json)
            self.ptjsonlib.add_vulnerability("PTWVMULTIVIEWS", request=response_dump["request"], response=response_dump["response"])
            return True
        else:
            ptprinthelper.ptprint(f"Multiviews: Disabled", "NOTVULN", not self.use_json)
            return False

    def _enumerate_files(self, url: str) -> None:
        """Enumerate files from URL"""
        original_url = url
        malformed_url = self._strip_url_extension(url)
        headers = dict({"Accept": "foo/foo"}, **self.headers)

        try:
            response = ptmisclib.load_url_from_web_or_temp(url=malformed_url, method="GET", headers=headers, proxies=self.proxies, timeout=self.timeout, redirects=self.redirects, verify=False, cache=self.cache)
        except requests.exceptions.RequestException as e:
            self.ptjsonlib.end_error(f"Cannot connect to: {original_url}", self.use_json)

        if response.status_code == 406:
            enumerated_files = re.findall('<a href="(.*)">', response.text)
            for found_file in enumerated_files:
                abs_path = f"{url.rsplit('/', 1)[0]}/{found_file}"
                rel_path = f"{url.split('/', 3)[-1]}/{found_file}"
                if abs_path in self.original_url_list and not self.with_requested_url:
                    continue
                path = abs_path if not self.without_domain else rel_path
                if path not in self.path_list:
                    self.path_list.append(path)
                    if self.use_json:
                        self.ptjsonlib.add_node(self.ptjsonlib.create_node_object("webpage", properties={"url": abs_path, "name": found_file, "WebPageType": self.ptpathtypedetector.get_type(path)}))

    def _strip_url_extension(self, url: str) -> str:
        o = urllib.parse.urlparse(url)
        path = o.path.rsplit("/", 1)
        if "." in path[-1]:
            new_path = f"{path[0]}/{path[-1].split('.', 1)[0]}"
            o = o._replace(path=new_path)
        return urllib.parse.urlunparse(o)

    def _get_urls(self, url: str, domain: str, file_urls: list) -> list:
        """Returns list of URLs"""

        if url and not (file_urls and domain):
            self.url_test = True
            return [self._parse_url(url)]

        elif (domain and file_urls) and not url:
            self.domain_file_test = True
            domain = self._adjust_domain(domain)
            url_list = self._read_file(file_urls, domain)
            return url_list

        elif file_urls and not (url and domain):
            self.file_test = True
            url_list = self._read_file(file_urls)
            return url_list

        elif domain and not file_urls:
            self.ptjsonlib.end_error("To use --domain parameter you need to supply --file parameter", self.use_json)

        else:
            self.ptjsonlib.end_error("Bad argument combination, see --help", self.use_json)

    def _adjust_domain(self, domain: str) -> str:
        """Adjusts provided <domain>"""
        o = urllib.parse.urlparse(domain)
        self._check_scheme(o.scheme)
        return domain + "/" if not o.path.endswith("/") else domain

    def _parse_url(self, url: str) -> str:
        """Checks whether the provided url is valid"""
        o = urllib.parse.urlparse(url)
        self._check_scheme(o.scheme)
        if len(o.path) in [0, 1]:
            self.ptjsonlib.end_error(f"URL with PATH to file is required (e.g. https://www.example.com/index.php)", self.use_json)
        return f"{o.scheme}://{o.netloc}{o.path}"

    def _check_scheme(self, scheme: str) -> None:
        """Checks whether provided scheme is valid"""
        if not re.match("http[s]?$", scheme):
            self.ptjsonlib.end_error(f"Missing or invalid scheme, supported schemes are: [HTTP, HTTPS]", self.use_json)

    def _read_file(self, filepath: str, domain: str = None) -> list:
        ptprinthelper.ptprint(f"Reading file: {filepath}", "TITLE", not self.use_json)
        try:
            with open(filepath, 'r') as fh:
                url_list = []
                for line in fh.readlines():
                    line = line.strip()
                    if domain:
                        path = urllib.parse.urlparse(line).path
                        while path.startswith("/"): path = path[1:]
                        while path.endswith("/"): path = path[:-1]
                        if not path: continue
                        url_list.append(domain+path)
                    else:
                        if validators.url(line) and re.match("http[s]?$", urllib.parse.urlparse(line).scheme):
                            url_list.append(line)
            return list(set(url_list))

        except (IOError, FileNotFoundError) as e:
            self.ptjsonlib.end_error(f"Cannot read file - {e}", self.use_json)

    def _get_output_file(self, filepath: str) -> typing.TextIO:
        """returns <output_file> file handler"""
        try:
            output_file = open(filepath, 'a')
            return output_file
        except IOError as e:
            self.ptjsonlib.end_error(f"Cannot output to file - {e}", self.use_json)

def get_help():
    return [
        {"description": ["Apache Multiviews detection & enumeration tool"]},
        {"usage": ["ptmultiviews <options>"]},
        {"tip": ["Use this program against existing web resources (eg. https://www.example.com/index.php)"]},
        {"usage_example": [
            "ptmultiviews -u https://www.example.com/",
            "ptmultiviews -u https://www.example.com/ --check-only",
            "ptmultiviews -d https://www.example.com/ -f filepaths.txt",
            "ptmultiviews -f urlList.txt",
        ]},
        {"options": [
            ["-u",   "--url",                    "<url>",            "Connect to URL"],
            ["-f",   "--file",                   "<file>",           "Load list of URLs from file"],
            ["-d",   "--domain",                 "<domain>",         "Domain to test (use with <file> argument)"],
            ["-co",  "--check-only",             "",                 "Check for multiviews without enumerating"],
            ["-wr",  "--with-requested-url",     "",                 "Includes requested source among enumerated results"],
            ["-wd",  "--without-domain",         "",                 "Enumerated files will be printed without domain"],
            ["-t",   "--threads",                "<threads>",        "Set number of threads (default 20)"],
            ["-p",   "--proxy",                  "<proxy>",          "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-T",   "--timeout",                "<timeout>",        "Set timeout (default 10)"],
            ["-c",   "--cookie",                 "<cookie>",         "Set cookie"],
            ["-ua",  "--user-agent",             "<ua>",             "Set User-Agent header"],
            ["-H",   "--headers",                "<header:value>",   "Set custom header(s)"],
            ["-o",   "--output",                 "<output>",         "Save output to file"],
            ["-r",   "--redirects",              "",                 "Follow redirects (default False)"],
            ["-C",   "--cache",                  "",                 "Cache HTTP communication (load from tmp in future)"],
            ["-v",   "--version",                "",                 "Show script version and exit"],
            ["-h",   "--help",                   "",                 "Show this help message and exit"],
            ["-j",   "--json",                   "",                 "Output in JSON format"],
        ]
        }]


def parse_args():
    parser = argparse.ArgumentParser(usage=f"{SCRIPTNAME} <options>")
    parser.add_argument("-u",  "--url",                  type=str)
    parser.add_argument("-d",  "--domain",               type=str)
    parser.add_argument("-f",  "--file",                 type=str)
    parser.add_argument("-o",  "--output",               type=str)
    parser.add_argument("-T",  "--timeout",              type=int, default=10)
    parser.add_argument("-t",  "--threads",              type=int, default=20)
    parser.add_argument("-p",  "--proxy",                type=str)
    parser.add_argument("-c",  "--cookie",               type=str)
    parser.add_argument("-ua", "--user-agent",           type=str, default="Penterep Tools")
    parser.add_argument("-H",  "--headers",              type=ptmisclib.pairs)
    parser.add_argument("-co", "--check-only",           action="store_true")
    parser.add_argument("-wd", "--without-domain",       action="store_true")
    parser.add_argument("-wr", "--with-requested-url",   action="store_true")
    parser.add_argument("-r",  "--redirects",            action="store_true")
    parser.add_argument("-C",  "--cache",                action="store_true")
    parser.add_argument("-v",  "--version",              action="version", version=f"{SCRIPTNAME} {__version__}")
    parser.add_argument("-j",  "--json",                 action="store_true")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptmultiviews"
    requests.packages.urllib3.disable_warnings()
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
    args = parse_args()
    script = PtMultiviews(args)
    script.run(args)


if __name__ == "__main__":
    main()
