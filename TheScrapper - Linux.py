#!/usr/bin/env python3
#"STN-TheScrapper - Linux"
__author__ = "Kartavya Trivedi"
__version__ = "1.0"
__date__ = "2021-12-15"


import sys
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
import os
import copy
import gzip
import subprocess
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote
import traceback



def EvaluateLogPaths():
    paths = []
    print("[.] Automatically evaluating the folders to which apps write logs ...")
    command = "lsof 2>/dev/null | grep '\\.log' | sed 's/.* \\//\\//g' | sort | uniq"
    PatchEval = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    output = PatchEval.communicate()[0].splitlines()
    for o in output:
        path = os.path.dirname(o)
        if isinstance(path, bytes):
            path = path.decode("utf-8")
        if path in paths: 
            continue
        paths.append(path)
        if args.debug:
            print("[D] Adding PATH: %s" % path)
    return paths

class TheScrapper(object):
    DetectStrings = ['${jndi:ldap:', '${jndi:rmi:/', '${jndi:ldaps:/', '${jndi:dns:/', '${jndi:nis:/', '${jndi:nds:/', '${jndi:corba:/', '${jndi:iiop:/']
    PlainStrings = {
        "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b#gistcomment-3991502": [
            " header with value of BadAttributeValueException: "
        ],
        "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b#gistcomment-3991700": [
            "at java.naming/com.sun.jndi.url.ldap.ldapURLContext.lookup(", 
            ".log4j.core.lookup.JndiLookup.lookup(JndiLookup"
        ],
        "https://github.com/Neo23x0/log4shell-detector/issues/5#issuecomment-991963675": [
            '${base64:JHtqbmRp'
        ], 
        "https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce/issues/1": [
            'Reference Class Name: foo'
        ]
    }

    def __init__(self, MaxDistance, debug, quick, summary):
        self.PrepareDetections(MaxDistance)
        self.debug = debug
        self.quick = quick
        self.summary = summary

    def DecodeLine(self, line):
        while "%" in line:
            LineBefore = line
            line = unquote(line)
            if line == LineBefore:
                break
        return line

    def CheckLine(self, line):
        DecodedLine = self.DecodeLine(line)

        for ref, strings in self.PlainStrings.items():
            for s in strings:
                if s in line or s in DecodedLine:
                    return s

        DecodedLine = DecodedLine.lower()
        linechars = list(DecodedLine)
        
        dp = copy.deepcopy(self.DetectionPad)
        
        for c in linechars:
            for DetectionString in dp:
                
                if c == dp[DetectionString]["chars"][dp[DetectionString]["level"]]:
                    
                    if dp[DetectionString]["level"] == 1 and not dp[DetectionString]["CurrentDistance"] == 1:
                        
                        dp[DetectionString]["CurrentDistance"] = 0
                        dp[DetectionString]["level"] = 0 
                    dp[DetectionString]["level"] += 1
                    dp[DetectionString]["CurrentDistance"] = 0
                
                if dp[DetectionString]["level"] > 0:
                    dp[DetectionString]["CurrentDistance"] += 1
                    
                    if dp[DetectionString]["CurrentDistance"] > dp[DetectionString]["MaxDistance"]:
                        dp[DetectionString]["CurrentDistance"] = 0
                        dp[DetectionString]["level"] = 0 
                
                if len(dp[DetectionString]["chars"]) == dp[DetectionString]["level"]:
                    return DetectionString

    def ScanFile(self, FilePath):
        MatchesInFile = []
        try:
            
            if "log." in FilePath and FilePath.endswith(".gz"):
                with gzip.open(FilePath, 'rt') as gzlog:
                    c = 0
                    for line in gzlog: 
                        c += 1
                        
                        if self.quick and not "2021" in line and not "2022" in line:
                            continue 
                        
                        result = self.CheckLine(line)
                        if result:
                            MatchesDict = {
                                "LineNumber": c,
                                "MatchString": result,
                                "line": line.rstrip()
                            }
                            MatchesInFile.append(MatchesDict)
            
            else:
                with open(FilePath, 'r') as logfile:
                    c = 0
                    for line in logfile:
                        c += 1
                        
                        if self.quick and not "2021" in line and not "2022" in line:
                            continue
                        # Analyze the line
                        result = self.CheckLine(line)
                        if result:
                            MatchesDict = {
                                "LineNumber": c,
                                "MatchString": result,
                                "line": line.rstrip()
                            }
                            MatchesInFile.append(MatchesDict)
        except UnicodeDecodeError as e:
            if self.debug:
                print("[E] Can't process FILE: %s REASON: most likely not an ASCII based log file" % FilePath)
        except PermissionError as e:
            print("[E] Can't access %s due to a permission problem." % FilePath)
        except Exception as e:
            print("[E] Can't process FILE: %s REASON: %s" % (FilePath, traceback.print_exc()))

        return MatchesInFile

    def ScanPath(self, path):
        matches = defaultdict(lambda: defaultdict())
        
        for root, directories, files in os.walk(path, followlinks=False):
            for filename in files:
                FilePath = os.path.join(root, filename)
                if self.debug:
                    print("[.] Processing %s ..." % FilePath)
                MatchesFound = self.ScanFile(FilePath)
                if len(MatchesFound) > 0:
                    for m in MatchesFound:
                        matches[FilePath][m['LineNumber']] = [m['line'], m['MatchString']]
                        
        if not self.summary:
            for match in matches:
                for LineNumber in matches[match]:
                    print('[!] FILE: %s LineNumber: %s DeobfuscatedString: %s LINE: %s' % (match, LineNumber, matches[match][LineNumber][1], matches[match][LineNumber][0]))
        # Result
        NumberofDetections = 0
        NumberOfFilesWithDetections = len(matches.keys())
        for FilePath in matches:
            NumberofDetections += len(matches[FilePath].keys())
       
        if NumberofDetections > 0:
            print("[!] %d files with exploitation attempts detected in PATH: %s" % (NumberOfFilesWithDetections, path))
            if self.summary:
                for match in matches:
                    for LineNumber in matches[match]:
                        print('[!] FILE: %s LineNumber: %d STRING: %s' % (match, LineNumber, matches[match][LineNumber][1]))
        else:
            print("[+] No files with exploitation attempts detected in path PATH: %s" % path)
        return NumberofDetections

    def PrepareDetections(self, MaxDistance):
        self.DetectionPad = {}
        for ds in self.DetectStrings:
            self.DetectionPad[ds] = {}
            self.DetectionPad[ds] = {
                "chars": list(ds),
                "MaxDistance": MaxDistance,
                "CurrentDistance": 0,
                "level": 0
            }

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='TheScrapper Exploitation Detectors')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', nargs='+', help='Path to scan', metavar='path', default='')
    group.add_argument('-f', nargs='+', help='File to scan', metavar='path', default='')
    group.add_argument('--auto', action='store_true', help='Automatically evaluate locations to which logs get written and scan these folders recursively (new default if no path is given)')
    parser.add_argument('-d', type=int, help='Maximum distance between each character', metavar='distance', default=40)
    parser.add_argument('--quick', action='store_true', help="Skip log lines that don't contain a 2021 or 2022 time stamp")
    parser.add_argument('--debug', action='store_true', help='Debug output')
    parser.add_argument('--summary', action='store_true', help='Show summary only')

    args = parser.parse_args()
    
    print("____ ___ _  _    _ _  _ ____          ___ _  _ ____ ____ ____ ____ ____ ___  ___  ____ ____ ")
    print("[__   |  |\ |    | |\ | |       __     |  |__| |___ [__  |    |__/ |__| |__] |__] |___ |__/ ")
    print("___]  |  | \|    | | \| |___           |  |  | |___ ___] |___ |  \ |  | |    |    |___ |  \ ")
    print(" ")
    print("  Version %s, %s" % (__version__, __author__))
    
    print("")
    DateScanStart = datetime.now()
    print("[.] Starting scan DATE: %s" % DateScanStart)
    
    
    l4sd = TheScrapper(MaxDistance=args.d, debug=args.debug, quick=args.quick, summary=args.summary)
    
    
    AllDetections = 0
    
    
    if args.f:
        files = args.f 
        for f in files:
            if not os.path.isfile(f):
                print("[E] File %s doesn't exist" % f)
                continue
            print("[.] Scanning FILE: %s ..." % f)
            matches = defaultdict(lambda: defaultdict())
            MatchesFound = l4sd.ScanFile(f)
            if len(MatchesFound) > 0:
                for m in MatchesFound:
                    matches[f][m['LineNumber']] = [m['line'], m['MatchString']]
                for match in matches:
                    for LineNumber in matches[match]:
                        print('[!] FILE: %s LineNumber: %s DeobfuscatedString: %s LINE: %s' % 
                            (match, LineNumber, matches[match][LineNumber][1], matches[match][LineNumber][0])
                        )
            AllDetections = len(matches[f].keys())
    
    
    else:
        
        paths = args.p
        
        AutoEvalPaths = False
        if args.auto:
            AutoEvalPaths = True

        if len(paths) == 0 and not AutoEvalPaths:
            print("[W] Warning: Please Select a path (-p path) otherwise, TheScrapper will activate the automatic path evaluation (--auto) for your convenience.")
            AutoEvalPaths = True
        
        if AutoEvalPaths:
            LogPaths = EvaluateLogPaths()
            paths = LogPaths
        
        for path in paths:
            if not os.path.isdir(path):
                print("[E] Error: Path %s doesn't exist" % path)
                continue
            print("[.] Scanning FOLDER: %s ..." % path)
            detections = l4sd.ScanPath(path)
            AllDetections += detections

    
    if AllDetections > 0:
        print("[!!!] %d exploitation attempts detected in the complete scan" % AllDetections)
        
    else:
        print("[.] No exploitation attempts detected in the scan")
    DateScanEnd = datetime.now()
    print("[.] Finished scan DATE: %s" % DateScanEnd)
    duration = DateScanEnd - DateScanStart
    mins, secs = divmod(duration.total_seconds(), 60)
    hours, mins = divmod(mins, 60)
    print("[.] Scan took the following time to complete DURATION: %d hours %d minutes %d seconds" % (hours, mins, secs))