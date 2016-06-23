import requests
import csv
from executioner import Executioner

class Hash(Executioner):

    def rescan(self, filename):
        f = open(filename, 'r')
        csv_f = csv.reader(f)
        count = 0
        files = list()

        #Rescanning the hashes in Virus Total
        for row in csv_f:
            count += 1
            hash = row[0]

            payload = {"resource": hash , "apikey": self.api_key}
            r = requests.get(self.rescanURL, params=payload)
            name = row[2].split('\\')[-1]
            files.push(name)
            print("[{}] Rescanning {}...".format(count,name))

        f.close()

    def check(self, filename):
        f = open(filename, 'r')
        csv_f = csv.reader(f)
        count = 0

        for row in csv_f:
            count += 1
            hash = row[0]
            payload = {"resource": hash , "apikey": self.api_key}
            r = requests.get(reportURL, params=payload)
            scans = r.json['scans']

            for name,result in scans.items():
                if result.get("detected") == "true":
                    malware_type = result.get("result")
                    print ("<!> {} : {} found this to be {}.".format(f, name,malware_type))

        f.close()
