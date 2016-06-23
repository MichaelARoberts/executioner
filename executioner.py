class Executioner:
    def __init__(self, api_key):
        self.rescanURL = "https://www.virustotal.com/vtapi/v2/file/rescan"
        self.scanURL = "https://www.virustotal.com/vtapi/v2/file/scan"
        self.reportURL = "https://www.virustotal.com/vtapi/v2/file/report"
        self.apiKey = api_key
