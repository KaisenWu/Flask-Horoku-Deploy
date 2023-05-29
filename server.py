# Import packages.
from flask import Flask,request
from flask_cors import CORS 
from werkzeug.utils import secure_filename
import requests
from datetime import datetime
import json
from flask_mysqldb import MySQL

# from flask_caching import Cache
from cachelib import SimpleCache

# Create the Flask app.
app = Flask(__name__)

# Define the cache.
cache = SimpleCache()


# Define the CORS.
CORS(app)

# MySQL configurations.
app.config['MYSQL_HOST'] = 'containers-us-west-161.railway.app'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'QeM5yAIPGwhRXojcaxu8'
app.config['MYSQL_DB'] ='railway'
app.config['MYSQL_PORT'] = 6223
mysql = MySQL(app)

# Store the api key and the urls.
my_api_key = "f8289ac2cf205b95f871fbac99d34480a22b0ab0892f621871e9651747911a7d"
get_report_url_pre = "https://www.virustotal.com/api/v3/files/"


# Define the routes.
@app.route("/upload", methods=["POST", "GET"])

# Define the upload function.
def upload():
    # Define the activites when the request method is POST.
    if request.method == "POST":
        reports = []
        # Check if the cache is empty.
        if cache.get("reports") == None:
            print("Cache is empty")
            # Get the file from the request.
            f=request.files['file']
            # Extract the hashes from the file.
            f.stream.seek(0)
            hashes = f.stream.readlines()
            hashes = [hash.decode('utf-8').replace("b'", "").replace("\r\n", "") for hash in hashes]   
            # Get the reports from the VirusTotal.
            headers = {
                "accept": "application/json",
                "x-apikey": my_api_key
            }            
            for hash in hashes:
                get_report_url = get_report_url_pre + hash
                response = requests.get(get_report_url, headers=headers)
                report = response.json()
                if 'data' in report:
                    engine_list = report['data']['attributes']['last_analysis_results'].keys()
                    if "Fortinet" in engine_list:
                        if report['data']['attributes']['last_analysis_results']['Fortinet']['result'] == None:
                            fortinet_result = "Not detected"
                        else:
                            fortinet_result = report['data']['attributes']['last_analysis_results']['Fortinet']['result']
                    else:
                        fortinet_result = "Not scanned by Fortinet"
                    detection_count = 0
                    for engine in engine_list:
                        if report['data']['attributes']['last_analysis_results'][engine]['result'] != None:
                            detection_count += 1
                    timestamp = report['data']['attributes']['last_analysis_date']
                    scan_date = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    reports.append({"hash": hash, "f_result": fortinet_result, "detection_cnt": detection_count, "date": scan_date})                          
                else:
                    reports.append({"hash": hash, "f_result": None, "detection_cnt": None, "date": None})
            
            # Store the reports in the cache.
            cache.set("reports", reports, timeout=86400)

            # Store the reports in the database.
            cur = mysql.connection.cursor()
            # Truncate the table first.
            cur.execute("TRUNCATE TABLE reports")
            for report in reports:
                cur.execute("INSERT INTO reports(hash_value, fortinet_detection_name, number_of_engines_detected, scan_date) VALUES(%s, %s, %s, %s)", (report['hash'], report['f_result'], report['detection_cnt'], report['date']))
                mysql.connection.commit()
            cur.close()

        # If the cache is not empty, get the hash values from the cache as a list.
        else:
            retrived_reports = cache.get("reports")
            retrived_hashes = []
            for report in retrived_reports:
                retrived_hashes.append(report['hash'])
            # Get the file from the request.
            f=request.files['file']
            # Extract the hashes from the file.
            f.stream.seek(0)
            request_hashes = f.stream.readlines()
            request_hashes = [hash.decode('utf-8').replace("b'", "").replace("\r\n", "") for hash in request_hashes]
            # Store the element in request_hashes list that is not in the retrived_hashes list.
            new_hashes = [hash for hash in request_hashes if hash not in retrived_hashes]
            if new_hashes:
                # Get the reports from the VirusTotal.
                headers = {
                    "accept": "application/json",
                    "x-apikey": my_api_key
                }     
                # Create a new list to store the new reports.
                new_reports = []
                for hash in new_hashes:
                    get_report_url = get_report_url_pre + hash
                    response = requests.get(get_report_url, headers=headers)
                    report = response.json()
                    if 'data' in report:
                        engine_list = report['data']['attributes']['last_analysis_results'].keys()
                        if "Fortinet" in engine_list:
                            if report['data']['attributes']['last_analysis_results']['Fortinet']['result'] == None:
                                fortinet_result = "Not detected"
                            else:
                                fortinet_result = report['data']['attributes']['last_analysis_results']['Fortinet']['result']
                        else:
                            fortinet_result = "Not scanned by Fortinet"
                        detection_count = 0
                        for engine in engine_list:
                            if report['data']['attributes']['last_analysis_results'][engine]['result'] != None:
                                detection_count += 1
                        timestamp = report['data']['attributes']['last_analysis_date']
                        scan_date = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                        new_reports.append({"hash": hash, "f_result": fortinet_result, "detection_cnt": detection_count, "date": scan_date})                          
                    else:
                        new_reports.append({"hash": hash, "f_result": None, "detection_cnt": None, "date": None})

                reports = new_reports
                cache_reports = retrived_reports + new_reports
                # Store the new reports in the cache.
                cache.clear()
                cache.set("reports", cache_reports, timeout=86400)
                # Store the reports in the database.
                cur = mysql.connection.cursor()
                # Truncate the table first.
                cur.execute("TRUNCATE TABLE reports")
                for report in reports:
                    cur.execute("INSERT INTO reports(hash_value, fortinet_detection_name, number_of_engines_detected, scan_date) VALUES(%s, %s, %s, %s)", (report['hash'], report['f_result'], report['detection_cnt'], report['date']))
                    mysql.connection.commit()
                cur.close()

            else:
                print("No new reports")
                for hash in request_hashes:
                    reports.append(retrived_reports[retrived_hashes.index(hash)])
                # Store the reports in the database.
                cur = mysql.connection.cursor()
                # Truncate the table first.
                cur.execute("TRUNCATE TABLE reports")
                for report in reports:
                    cur.execute("INSERT INTO reports(hash_value, fortinet_detection_name, number_of_engines_detected, scan_date) VALUES(%s, %s, %s, %s)", (report['hash'], report['f_result'], report['detection_cnt'], report['date']))
                    mysql.connection.commit()
                cur.close()

            print(cache.get("reports"))
    
        return {"reports": reports}
                 
    else:
        # Start a connection with the database.
        cur = mysql.connection.cursor()
        # Get the reports from the database.
        cur.execute("SELECT * FROM reports")
        reports_tuple = cur.fetchall()
        reports = []
        for report in reports_tuple:
            reports.append({"hash": report[1], "f_result": report[2], "detection_cnt": report[3], "date": report[4]})
        # After getting the reports, truncate the table.
        cur.execute("TRUNCATE TABLE reports")
        # Commit the changes and close the connection.
        mysql.connection.commit()
        cur.close()
        # Return the reports to the client.
        return {"reports": reports}  


if __name__ == "__main__":
    app.run(debug=True)