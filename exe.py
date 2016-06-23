import requests
from executioner import Executioner

class Exe(Executioner):

    def get_resource_ids(folder, url):
        host = "www.virustotal.com"
        fields = [("apikey", self.api_key)]
        resource_ids = list()
        for root, dirs, files in os.walk(folder):
            for f in files:
                if f.endswith(".exe"):
                    file_data = open(os.path.join(root, f), "rb").read()

                    # Packaging read file
                    files = [("file", f, file_data)]

                    # Replicating a form POST
                    json = postfile.post_multipart(host, url, fields, files)

                    # Getting the file's resource id from json
                    resource_id = json['resource']

                    resource_ids.append(resource_id)

        return resource_ids

    def scan(folder):
        resource_ids = get_resources_ids(folder, self.scanURL)

    def rescan(folder):
        resource_ids = get_resources_ids(folder, self.rescanURL)

        for resource_id in resource_ids:
            payload = {"resource" : resource_id,
                       "apikey" : self.api_key}

            r = requests.get(self.reportURL, params=payload)
            r_json = r.json()
            scans = r.json['scans']

        for name,result in scans.items():
            if result.get("detected") == "true":
                malware_type = result.get("result")
                print ("<!> {} : {} found this to be {}.".format(f, name,malware_type))
