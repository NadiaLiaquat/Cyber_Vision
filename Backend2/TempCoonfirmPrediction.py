import hashlib
import requests


class ConfirmPredition:
    def __init__(self, fileName):
        self.fileName = fileName

    def generateFileHashes(self):
        with open(self.fileName, "rb") as f:
            bytes_read = f.read()
            readable_hash = hashlib.sha256(bytes_read).hexdigest()

            print(readable_hash)
            # "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"
            return readable_hash

    def getDataOfFile(self, hash_string):
        res = requests.post(url="https://mb-api.abuse.ch/api/v1/", data={
            "query": "get_info",
            "hash": hash_string,
        })

        response_data = res.json()
        print(res.json())
        if response_data["query_status"] == "ok":
            data_item = response_data["data"][0]

            # Create a dictionary to store the information
            file_info = {
                "SHA256 Hash": data_item["sha256_hash"],
                "File Name": data_item["file_name"],
                "File Size": data_item["file_size"],
                "File Type": data_item["file_type"],
                "First Seen": data_item["first_seen"],
                "Last Seen": data_item["last_seen"],
                "Signature": data_item["signature"],
                "ImpHash": data_item["imphash"],
                "AllTags": data_item["tags"]

            }
            triage_info = data_item.get("vendor_intel", {}).get("Triage", {})
            file_info["Triage"] = {
                "Malware Family": triage_info.get("malware_family", "Unknown"),
                "Score": triage_info.get("score", "Unknown"),
                "Link": triage_info.get("link", "Unknown"),
                "Tags": triage_info.get("tags", []),

            }
            # tags = data_item["tags"]
            # print(f"Here Is All Tags \n {tags}")

            return file_info
        elif response_data["query_status"] != "ok":
            # print("Error: Hash not found or other API issue.")
            return "Not Malware"

    def verifyPredictions(self):
        hashes = self.generateFileHashes()
        file_information = self.getDataOfFile(hash_string=hashes)
        print(f"Here Is All Tags \n {file_information.get('AllTags')}")
        # print(file_information)
        # if file_information == "Not Malware":
        #     return "Not Malware"
        # else:
        #     return file_information


# if __name__ == '__main__':
#     obj = ConfirmPredition(
#     fileName="E:\Python-Projects\\fyp_file4\exe_file\keylogger\\1d6694b7aa3340c6d744ec8f3d1e64caf255e1e5c27057f5bc43036374b69bb4.exe")
#     # file_information = obj.verifyPredictions()
#     obj.verifyPredictions()
