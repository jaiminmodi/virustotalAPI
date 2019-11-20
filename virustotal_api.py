import requests
import logging
import time
import datetime


if __debug__:
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s')

class extract_data:
    def __init__(self, api_key):
        super(extract_data, self).__init__()
        self.data = []
        self.api_key = api_key
        self.virustotal_report_url = 'https://www.virustotal.com/vtapi/v2/file/report'


    def add_data(self, file):

        try:
            file_open = open(file, 'r')
            hash_list = [line.rstrip('\n') for line in file_open.readlines()]
            logging.info('File loaded. Total hashes: ' +str(len(hash_list)))
            logging.info('Loading data in dictionary')
        except:
            logging.info("Unable to load the file: " +str(file))

        for i in hash_list:
            logging.info('Loading data for hash: ' +str(i))
            params = {'apikey': self.api_key, 'resource': i}
            response = requests.get(self.virustotal_report_url, params=params)

            if response.status_code == 200:
                if response.json()['response_code'] == 1:
                    start_time = time.time()
                    jsonRaw = response.json()
                    if 'Fortinet' in jsonRaw['scans'].keys():
                        #self.data[jsonRaw['md5']] = [jsonRaw['scans']['Fortinet']['result'], jsonRaw['positives'], jsonRaw['scan_date']]
                        self.data.append({'md5': jsonRaw['md5'], 'detection_name': jsonRaw['scans']['Fortinet']['result'], 'positives' : jsonRaw['positives'], 'scan_date' : jsonRaw['scan_date']})
                        logging.info('Loading complete: ' + str(i))
                    time.sleep(15)
                    total_time = datetime.timedelta(seconds=time.time() - start_time)
                    logging.info("Time : " + str(total_time))

                elif response.json()['response_code'] == 0:
                    logging.info(response.json()['verbose_msg'])
                    time.sleep(15)
                    continue

                elif response.json()['response_code'] == -2:
                    logging.info("The requested hash is still queued for analysis: " +str(i))
                    time.sleep(15)
                    continue

                else:
                    logging.info("The hash could not be processed: " +str(i))
                    continue

            elif response.status_code == 204:
                logging.info("Request rate limit exceeded. You are making more requests than allowed.")
                break

            elif response.status_code == 400:
                logging.info("Bad request. Your request was somehow incorrect.")
                break

            elif response.status_code == 403:
                logging.info("Forbidden. You don't have enough privileges to make the request.")
                break

            else:
                logging.info("Oops!! Something went really wrong!!")
                break

        file_open.close()
        return self.data

#VIRUSTOTAL_API_KEY = 'e216fc5c98503ea826c78944954ff8dcf5fdc5cc1bda8c641bc73ac9d8eec6c2'
