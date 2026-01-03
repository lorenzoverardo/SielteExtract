import requests, datetime, hashlib, hmac, jwt
from urllib3.util import SKIP_HEADER

# Change to spoof another device - this is how it will show up in your list of devices
device_model = "SM-S936B"
# Set to True to enable debug
debug = False 

api_base = "https://myid.sieltecloud.it/mobileapi/"
headers = {
    "User-Agent": SKIP_HEADER,
    "Accept-Encoding": SKIP_HEADER,
    "Accept": None,
    "Connection": None,
}

def auth(cf: str, password: str) -> object:
    url = api_base + "verifyCredentials"
    data = {
        "fiscalNumber": cf,
        "userPassword": password
    }
    s = requests.Session()
    s.headers = {}
    response = s.post(url, data=data, headers=headers, timeout=60)
    if debug:
        print("verifyCredentials: ", response.text)
    return response.json()

def create_api_token(user_id: str, secret_key: str) -> str:
    payload = {
        "str": datetime.datetime.now(datetime.UTC).strftime("%d/%m/%Y %H:%M:%S"),
        "usetz": "True"
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")

def generate_token(cf: str, auth_token: str, password: str) -> object:
    url = api_base + "generateTokenByApp"
    data = {
        "authToken": auth_token,
        "fiscalNumber": cf,
        "userPassword": password,
        "model": device_model
    }
    s = requests.Session()
    s.headers = {}
    response = s.post(url, data=data, headers=headers, timeout=60)
    if debug:
        print("generateTokenByApp: ", response.text)
    if response:
        result = response.json()
        if result["errore"] == "":
            return result
    return None

def check_otp_code(cf: str, auth_token: str, code: str) -> object:
    url = api_base + "verifyOTPCode"
    data = {
        "authToken": auth_token,
        "fiscalNumber": cf,
        "code": code
    }
    s = requests.Session()
    s.headers = {}
    response = s.post(url, data=data, headers=headers, timeout=60)
    response.raise_for_status()
    if debug:
        print("verifyOTPCode: ", response.text)    
    return response.json()
    
def send_otp_code(cf: str, auth_token: str) -> bool:
    url = api_base + "sendOTPCode"
    data = {
        "authToken": auth_token,
        "fiscalNumber": cf
    }
    s = requests.Session()
    s.headers = {}
    response = s.post(url, data=data, headers=headers, timeout=60)
    if debug:
        print("sendOTPCode: ", response.text)   
    if response is not None:
        result = response.json()
        return result is not None and result["errore"] == ""
    else:
        return False

def main():

    print("""You must read the entire README on https://github.com/lorenzoverardo/SielteExtract/blob/main/README.md before continuing.
It contains important information, such as:
- This product comes with no warranty or support, if something goes wrong you're basically on your own
- We are not affiliated with Sielte S.p.A., this is not an official product
- After entering the SMS code, you will be logged out of the MySielteID app (but you will be able to log back in at any time)""")

    if(input("Enter CONTINUE if you've read and understood the entire README, and still wish to continue: ") != "CONTINUE"):
        print("Operation aborted.")
        return

    cf = input("Fiscal code: ")
    password = input("Password: ")

    print("Starting authentication...")
    auth_obj = auth(cf, password)
    secret_key = ""
    try:
        secret_key = auth_obj["secretKey"]
        if debug:
            print("Got secretKey:", secret_key)
    except KeyError:
        print("secretKey missing from server reply. Have you entered the correct credentials?")
        return

    print("Generating JWT token...")
    auth_token = create_api_token(cf, secret_key)
    if debug:
        print("Generated token:", auth_token)

    print("Sending SMS...")
    if not send_otp_code(cf, auth_token):
        print("SMS sending error")
        return
    print("SMS is sent")

    otp = input("SMS code: ")
    print("Checking the code and getting new secretKey...")
    check_otp_obj = check_otp_code(cf, auth_token, otp)
    try:
        secret_key = check_otp_obj["secretKey"]
        if debug:
            print("Got new secretKey:", secret_key)
    except KeyError:
        print("new secretKey missing from server reply. Have you entered the correct code?")
        return

    print("Generating new JWT token...")
    auth_token = create_api_token(cf, secret_key)
    if debug:
        print("Generated token:", auth_token)

    print("Finalizing login and getting TOTP secret...")
    generate_token_obj = generate_token(cf, auth_token, password)
    secret = ""
    try:
        secret = generate_token_obj["secret"]
        if debug:
            print("Got secret:", secret)
    except KeyError:
        print("secret missing from server reply")
        return

    seed = "otpauth://totp/SielteID?secret=" + secret + "&algorithm=SHA1&digits=6&period=60"
    print("The TOTP seed is:", seed)

if __name__ == '__main__':
    main()
