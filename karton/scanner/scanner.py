from karton.core import Config,Karton, Resource, Task
import os
import sys
import logging
from .__version__ import __version__
from polyswarm_api.api import PolyswarmAPI
import sys
import hashlib
import tempfile
import polyunite
from datetime import datetime


def is_file_greater_than_30mb(file_path):
    # Get the size of the file in bytes
    file_size_bytes = os.path.getsize(file_path)

    # Convert bytes to megabytes
    file_size_mb = file_size_bytes / (1024 ** 2)

    # Check if the file size is greater than 30 MB
    return file_size_mb > 30

class PolySwarmKarton(Karton):
    """
    Scan Files using PolySwarm developed by Bormaa
    """

    identity = "karton.polyswarm-scanner"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "sample",
            "stage": "recognized",
            "kind": "runnable",
            "platform": "win32"
        }, {
            "type": "sample",
            "stage": "recognized",
            "kind": "runnable",
            "platform": "win64"
        },
        {
            "type": "sample",
            "stage": "recognized",
            "kind": "document",
            "platform": "win32"
        },
        { 
            "type": "sample",
            "stage": "recognized",
            "kind": "runnable",
            "platform": "linux"
        }
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.api=PolyswarmAPI(key=os.getenv("POLYSWARM_API"), community="default")
            
    def search(self,hash):
        try:
            results = self.api.search(hash)

            for result in results:
                if result.failed:
                    print(f'Failed to get result.')
                    return ""
                    break
                else:
                    return result
        except Exception as e :
                return ""
    def scan(self,sample):
        self.positives = 0
        self.total = 0
        hash=sample.metadata['sha256']
        self.log.info(f"File hash {hash}")
        detections={}
        result=self.search(hash)
        if result=="":
            self.log.info("Not found.... uploading file")
            data=sample.content
            temp_dir = tempfile.gettempdir()
            random_filename = next(tempfile._get_candidate_names())
            temp_file_path = os.path.join(temp_dir, random_filename)
            with open(temp_file_path, 'wb') as temp_file:
                temp_file.write(data)
            self.log.info(f"Temp file {temp_file_path}")
            if is_file_greater_than_30mb(temp_file_path):
                os.remove(temp_file_path)
                self.log.info("File is greater Than 30MB skipping")
                return False


            instance = self.api.submit(temp_file_path)
            result = self.api.wait_for(instance)
            os.remove(temp_file_path)
        else:
            self.log.info("Hash found")
        if result.polyscore==None:
            instance = self.api.rescan(hash)
            result = self.api.wait_for(instance)
        if result.polyscore<0.5:
            comparison_date = datetime(2022, 1, 1, 0, 0, 0)
            if result.last_seen < comparison_date:
                instance = self.api.rescan(hash)
                result = self.api.wait_for(instance)

        if result.failed:
            self.log.info("Failed to get results")
            sys.exit()
        for assertion in result.assertions:
            if assertion.verdict:
                try:
                    
                    detections[assertion.engine_name]=assertion.metadata.get("malware_family")
                except:
                    self.log.info(f"Failed to check engine {assertion.engine_name}")
                self.positives += 1
            self.total += 1
        self.score=result.polyscore
        polyfamily=polyunite.analyze(detections)
        self.family=polyfamily.infer_name()
        self.detections=detections
        return True
        

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        self.log.info("Starting processing new file")
        done=self.scan(sample)
        if done:
            
            if float(self.score)>0.7:
                
                tag_task = Task(
                    {"type": "sample", "stage": "analyzed"},
                    payload={"sample": sample, "tags": ["PolySwarm:malicious"],
                    "attributes": {"polyswarm-score":[f"{self.score}"],"polyswarm-detections":[f"{self.positives} / {self.total}"],
                                   "polyswarm-antivirus":[f"{self.detections}"],
                                   "polyswarm-family":[f"{self.family}"]
                                   
                                   }
                    }
                )
            elif float(self.score)<0.4:
                tag_task = Task(
                    {"type": "sample", "stage": "analyzed"},
                    payload={"sample": sample, "tags": ["PolySwarm:benign"],
                    "attributes": {"polyswarm-score":[f"{self.score}"],"polyswarm-detections":[f"{self.positives} / {self.total}"],
                                   "polyswarm-antivirus":[f"{self.detections}"],
                                   "polyswarm-family":[f"{self.family}"]
                                   
                                   }
                    }
                )
            else:
                tag_task = Task(
                    {"type": "sample", "stage": "analyzed"},
                    payload={"sample": sample,
                    "attributes": {"polyswarm-score":[f"{self.score}"],"polyswarm-detections":[f"{self.positives} / {self.total}"],
                                   "polyswarm-antivirus":[f"{self.detections}"],
                                   "polyswarm-family":[f"{self.family}"]
                                   
                                   }
                    }
                )
            self.send_task(tag_task)
