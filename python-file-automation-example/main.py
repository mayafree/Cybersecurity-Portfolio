# time data normalization ( person-readable -> epoch )
from datetime import datetime

# data durability & secure file management
import os
import tempfile


# this example script & its documentation demonstrates the following:
# 1 - programming/scripting & automation
# 2 - data normalization & validation
# 3 - nonstandard database management
# 4 - secure file management
# 5 - access control
# 6 - file parsing
# 7 - algorithms

# I avoided using a CSV / data management library to demonstrate an ability to work even with messy data.


# securely read a file
# use file descriptor approach to reduce race condition attack surface
def secure_read(file_path: str):
    # get OS-specific file path
    file_path_norm = os.path.normpath(file_path)

    # read only
    flags = os.O_RDONLY

    # on applicable operating systems, apply O_NOFOLLOW flag to throw exceptions
    # instead of following symlinks
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(file_path_norm, flags)

        # in a real world scenario, perform OS-specific validation logic here

        content = os.read(fd, os.stat(fd).st_size).decode("utf-8")
        os.close(fd)
        return content

    except FileNotFoundError:
        print(f"Unable to read {file_path_norm}: File not found")
    except OSError:
        print(f"Unable to read {file_path_norm}: Specified path is likely a symbolic link")
    return ""


# write to a temporary file and replace the target file with it
# note: this reduces chances of data corruption during write interruptions
def atomic_write(file_path: str, content: str):
    # get OS-specific file path
    file_path_norm = os.path.normpath(file_path)

    # create temporary file in same directory
    fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(file_path_norm))

    try:
        with os.fdopen(fd, 'w') as file:
            # write to python's buffer
            file.write(content)

            # push data from python's buffer to OS
            file.flush()

            # force OS to write to disk
            os.fsync(file.fileno())

        # replace target file
        os.replace(temp_path, file_path_norm)
        print(f"File saved! {file_path_norm}")
        separator()
    except Exception:
        # clean up if something goes wrong
        os.unlink(temp_path)
        raise


# split a string into a list of lines
# some strings contain whitespaces aside from newlines, so use \n (new line character) as delimiter
# splitting by \n can introduce blank lines into output lists, so use strip() to clean that up
def string_to_lines(to_split: str):
    return to_split.strip().split("\n")


# join a list into a single string separated by new lines
def lines_to_string(to_join: list):
    return "\n".join(to_join)


# determine if an IPv4 address is valid
# IPv4 addresses consist of 4 integers between 0 and 255 separated by dots.
# so they're fairly easy to validate.
def validate_ipv4(address: str):
    valid = True
    octets = address.split(".")

    # doesn't have 4 octets? not an ipv4
    if len(octets) != 4:
        return False

    # octets outside normal range? not an ipv4
    for octet in octets:
        octet_int = int(octet)
        if octet_int < 0 or octet_int > 255:
            valid = False
            break

    return valid


# attempt to remove all entries in one list from another list
def remove_entries_from_list(main_list: list, removal_list: list):
    print(f"Attempting to remove {len(removal_list)} items... {removal_list}")
    print(f"Start: {len(main_list)} {main_list}")
    items_removed = 0

    for line in removal_list:
        # we might encounter duplicate lines, so use a while loop
        while line in main_list:
            main_list.remove(line)
            items_removed += 1

    print(f"Stop:  {len(main_list)} {main_list}")
    print(f"{items_removed} items successfully removed!")
    separator()


# add a list of IPv4s to another list if they're valid and not duplicates
def add_ipv4s_to_list(main_list: list, addition_list: list):
    print(f"Attempting to add {len(addition_list)} items... {addition_list}")
    print(f"Start: {len(main_list)} {main_list}")
    items_added = 0

    for line in addition_list:
        if line not in main_list and validate_ipv4(line):
            main_list.append(line)
            items_added += 1

    print(f"Stop:  {len(main_list)} {main_list}")
    print(f"{items_added} items successfully added!")
    separator()


# separate print output to make it somewhat more readable
def separator():
    print("--------------------------------------------------")


# normalize log file lines into a more python-accessible format
# -> normalize boolean strings into boolean datatype
# -> normalize person-readable time into epoch time
# -> enable looking up values from field names
def get_normalized_log_list(log_list: list):
    # fewer than 2 lines means the logs are missing either field names or data
    if len(log_list) < 2:
        print("log data is not present. aborting...")
        return []

    field_names = log_list[0].split(",")

    # list of dictionaries
    normalized_log_list = []

    # parse data in the log list to access data in individual cells
    # use slice notation to avoid iterating over the field names
    for line in log_list[1:]:
        cells = line.split(",")

        # ignore lines that are missing data
        if len(cells) < len(field_names):
            continue

        # create a dictionary. fill it with key-value pairs
        # the keys are field names, and the values are the contents of the fields
        # this makes it easy to look up the data by name.
        # note: in real world conditions, a CSV library would manage something like this.
        normalized_line = {}
        for index, field in enumerate(field_names):
            normalized_line[field] = cells[index]

        normalized_log_list.append(normalized_line)

    # ----- it's data normalization time! -----

    # make sure the field we're normalizing still exists:
    # the log data structure may have been changed
    if "time" in field_names:
        for line in normalized_log_list:
            # normalize person-readable time into epoch time, which is the number of seconds since jan 01 1970
            # epoch time is easier for programs to do calculations with, so we'll need time in that format
            line["time"] = int(datetime.strptime(line["time"], "%Y-%m-%d %H:%M:%S").timestamp())

    if "success" in field_names:
        for line in normalized_log_list:
            # normalize string booleans to python's boolean datatype
            line["success"] = line["success"] == "true"

    return normalized_log_list


# use a class to contain attributes & methods related to logging in
class AuthenticationManager:
    # [this many failed login attempts] from an IP address within [this span of time]
    # will block an IP from making any additional login attempts.
    # note: in real-world conditions, these would be loaded from a configuration file.
    limit_login_attempts = 3
    limit_login_interval = 60 * 3

    log_list = []
    allow_list = []

    def update(self, log_list: list, allow_list: list):
        self.log_list = log_list
        self.allow_list = allow_list

    # pretend to log in to simulate an access control system
    # note: in real world conditions, we would want to keep a cache of relevant data.
    # reading the entire log file after every login attempt would introduce a vulnerability
    # to DoS (Denial of Service) attacks.
    def login(self, time_stamp: int, user_name: str, ip_address: str):
        print(f"[{time_stamp}] User \"{user_name}\" attempting login from {ip_address}")

        # check allow list for user's IP address (simulate access control)
        # note: IP addresses can be spoofed by an attacker. this should be just one line of defense
        if ip_address in self.allow_list:
            print(f"{ip_address} is in the allow list!")
        else:
            print(f"{ip_address} is not in the allow list! ACCESS DENIED")
            return

        # check for failed login attempts from connecting IP within a timespan
        # (simulate brute force attack mitigation)
        # note: in real world conditions, an attacker could use multiple IP addresses
        # to bypass this kind of security control. A firewall can help prevent this.
        normalized_log_list = get_normalized_log_list(self.log_list)

        failed_login_attempts = 0

        # the data structure of the logs may change in the future, so check to see
        # if these fields are in a log line prior to doing anything to avoid crashes
        required_fields = {"ip_address", "success", "time"}

        for data in normalized_log_list:

            # make sure the log format hasn't become incompatible with the script
            should_check_log = True
            for field in required_fields:
                if field not in data.keys():
                    print(f"authentication: key \"{field}\" missing from log entry, ignoring this line...")
                    should_check_log = False

            if (should_check_log and ip_address == data["ip_address"]
                    and data["success"] is False
                    and time_stamp - data["time"] <= self.limit_login_interval):
                failed_login_attempts += 1

        if failed_login_attempts >= self.limit_login_attempts:
            print(f"Too many failed login attempts from {ip_address} - ACCESS DENIED")
            return

        # all checks passed! good to go
        print(f"Access granted! Welcome back, {user_name}!")


def main():
    separator()

    # for consistency, we'll assume the script always runs at this exact time
    fake_time = "2026-01-13 16:00:00"
    fake_time_stamp = int(datetime.strptime(fake_time, "%Y-%m-%d %H:%M:%S").timestamp())

    # load allow list, IPs to add and remove, and recent login attempts
    allow_list_string = secure_read("mock_data/_allow_list_unmodified.txt")  # pretend this is allow_list.txt
    remove_list_string = secure_read("mock_data/ips_to_remove.txt")
    addition_list_string = secure_read("mock_data/ips_to_add.txt")
    log_string = secure_read("mock_data/login_attempts_2026-01-13.txt")

    # split contents of loaded files into lists
    allow_list = string_to_lines(allow_list_string)
    remove_list = string_to_lines(remove_list_string)
    addition_list = string_to_lines(addition_list_string)
    log_list = string_to_lines(log_string)

    # display the log data we're working with as field names & attributes
    if log_list:
        print(log_list[0])
    for line in get_normalized_log_list(log_list):
        print(line)

    separator()

    # throw some junk data into the IP addition list to demonstrate ipv4 validation
    addition_list.append("JUNK DATA EXAMPLE")

    # update the allow list by removing unwanted entries & adding new entries
    add_ipv4s_to_list(allow_list, addition_list)
    remove_entries_from_list(allow_list, remove_list)

    # save the changes made to allow_list.txt
    atomic_write("mock_data/allow_list.txt", lines_to_string(allow_list))

    auth_manager = AuthenticationManager()
    auth_manager.update(log_list, allow_list)

    # fail: IP not in allow list
    auth_manager.login(fake_time_stamp - 12, "dave", "120.60.120.60")
    separator()

    # fail: IP recently failed too many login attempts
    auth_manager.login(fake_time_stamp - 5, "dave", "195.97.229.41")
    separator()

    # success: IP in allow list & no recent failed logins from this IP
    auth_manager.login(fake_time_stamp - 36, "arnold", "100.46.36.241")
    separator()


if __name__ == "__main__":
    main()
