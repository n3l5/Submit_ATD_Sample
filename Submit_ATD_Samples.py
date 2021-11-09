import os
import sys
import base64
import json
import requests
import hashlib
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def md5hash(file):
    BSIZE = 65536
    hnd = open(file, 'rb')
    hashmd5 = hashlib.md5()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashmd5.update(info)
    return hashmd5.hexdigest()

def submit_file(file):
    data = {"data": {"vmProfileList": "24", "submitType": "0", "analyzeAgain": "1", }}
    try:
        files = {'amas_filename': open(file, 'rb')}
        res = requests.post(atdurl + "fileupload.php", headers=sessionheaders, files=files, data={"data": json.dumps(data)}, verify=False, )
        if res.status_code == 200:
            for result in res.json()["results"]:
                taskid = result["taskId"]
                submittedfile = result["file"]
                fileMd5 = result["md5"]
                fileSHA1 = result["sha1"]
                fileSHA256 = result["sha256"]
                filemimetype = res.json()["mimeType"]
                print("<[ ATD STATUS: Successful submitted File. TaskID {0} ]>".format(str(taskid)))
                print('------------------------------------------------------------------------')
                print("Submitted file: {0}".format(str(submittedfile)))
                print("Filetype: {0}".format(str(filemimetype)))
                print('')
                print("MD5:    {0}".format(str(fileMd5)))
                print("SHA1:   {0}".format(str(fileSHA1)))
                print("SHA256: {0}".format(str(fileSHA256)))
                print('------------------------------------------------------------------------')
                print()                
        else:
            print("ATD ERROR: Something went wrong in {0}. Error: {1}".format(sys._getframe().f_code.co_name, str(res.text)))
            sys.exit()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("ATD ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno, error=str(e), ))
        sys.exit()

def logout():
    try:
        res = requests.delete(atdurl + "session.php", headers=sessionheaders, verify=False)
        if res.status_code == 200:
            print("ATD STATUS: Successful log out")
            print()
        else:
            print("ATD ERROR: Something went wrong in {0}. Error: {1}".format(sys._getframe().f_code.co_name, str(res.text)))
            sys.exit()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("ATD ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno, error=str(e), ))
        sys.exit()

input_param = sys.argv[1]
input_files = []
unique_files = []

# Validate a parameter was provided as an argument
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s sample' % sys.argv[0])

# If the supplied parameter is a file validate it exists
if not os.path.exists(input_param):
    sys.exit('File {} doesn\'t exist'.format(input_param))

# Check if the supplied parameter is a directory
if os.path.isdir(input_param):
    print()
    print('You have supplied a directory')
    print()
    for (dirpath, dirnames, filenames) in os.walk(input_param):
        for file in filenames:
            file_path = os.path.join(dirpath, file)
            file_hash = md5hash(file_path)
            if file_hash not in unique_files:
                unique_files.append(file_hash)
                input_files.append(file_path)
            else:
                os.remove(file_path)            
else:
    # Append the provided parameter to input_files
    input_files.append(input_param)

#ATD Settings
atdurl = "https://YOUR.ATDSERVER.HERE/php/"

#Hardcoded username/passwords are a bad idea. Set up a stand alone account for this on your ATD system. 
atdUser = 'YOURATDUSERNAMEHERE'
atdPwd = 'YOURATDPASSWORDHERE'
creds = base64.b64encode(((atdUser) + ":" + (atdPwd)).encode())

try:
    authheaders = {"VE-SDK-API": creds, "Content-Type": "application/json", "Accept": "application/vnd.ve.v1.0+json", }
    res = requests.get(atdurl + "session.php", headers=authheaders, verify=False)
    if res.status_code == 200:
        results = res.json()["results"]
        sheaders = results["session"] + ":" + results["userId"]
        sessionheaders = {"VE-SDK-API": base64.b64encode(sheaders.encode()), "Accept": "application/vnd.ve.v1.0+json", "accept-encoding": "gzip;q=0,deflate,sdch", }
    else:
        print("ATD ERROR: Something went wrong in {0}. Error: {1}".format(sys._getframe().f_code.co_name, str(res.text)))
        sys.exit()
except Exception as e:
    exc_type, exc_obj, exc_tb = sys.exc_info()
    print("ATD ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(location=__name__,funct_name=sys._getframe().f_code.co_name,line_no=exc_tb.tb_lineno,error=str(e),))
    sys.exit()

number_of_files = len(input_files)

print("--------------------")
print("SUBMITTING [ {0} ] FILES".format(str(number_of_files)))
print("--------------------")
print()
for file in input_files:
    files = {'amas_filename': open(file, 'rb')}
    submit_file(file)
print("----------------")
print("SUBMISSIONS DONE")
print("----------------")
logout()