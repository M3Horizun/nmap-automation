import nmap
import json

scanner = nmap.PortScanner()

print("Welcome, to the automation nmap Python script!")
print("%s%s%s" % ("<", "-"*15, ">"))
pref = json.load(open("./config/preferences.json", 'r'))


clear = 'clear'
if pref["os"] is None:
    os = input("Please choose your operating system\n\nwin\nmac\nlinux").lower()
    os_list = ["win", "linux", "mac"]
    invalid_operating_system = True
    for _os in os_list:
        if os == _os:
            invalid_operating_system = False
    if invalid_operating_system:
        while invalid_operating_system:
            os = input(
                "Invalid operating system\nPlease choose your operating system\n\nwin\nmac\nlinux").lower()
            for _os in os_list:
                if os == _os:
                    invalid_operating_system = False

    # Changing preferences "os" to the operating system

    pref['os'] = os
    json.dump(pref, open("./config/preferences.json", 'w'))
    pref = json.load(open("./config/preferences.json", 'r'))

    # making variable "clear" = the operating systems way of clearing the screen

    if os == "win":
        clear = "cls"
    elif os == "linux" or os == "mac":
        clear = "clear"


def select_scan_type():
    try:
        prompt = int(input("""Enter Number That Corresponds To The Scan You Would Like To Do:
        1) SYN ACK 
        2) UDP
        3) Comprehensive
        """))

    except ValueError:
        invalid = True
        while invalid:
            print("Unable to match input! Please try again!")
            try:
                prompt = int(input("""Enter Number That Corresponds To The Scan You Would Like To Do:
                1) SYN ACK 
                2) UDP
                3) Comprehensive
                """))
            except ValueError:
                continue
            # Check if number taken in is valid
                if prompt < 1 or prompt > 3:
                    continue
            if prompt < 1 or prompt > 3:
                continue

            invalid = False
    if prompt < 1 or prompt > 3:
        invalid = True
        while invalid:
            print("Unable to match input! Please try again!")
            try:
                prompt = int(input("""Enter Number That Corresponds To The Scan You Would Like To Do:
                1) SYN ACK 
                2) UDP
                3) Comprehensive
                """))
            except ValueError:
                continue
            # Check if number taken in is valid
                if prompt < 1 or prompt > 3:
                    continue
            if prompt < 1 or prompt > 3:
                continue

            invalid = False
    return prompt


scan_type = select_scan_type()
