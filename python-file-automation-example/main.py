# time data normalization ( person-readable -> epoch )
from datetime import datetime


# this example script & its documentation demonstrates the following:
# 1 - programming/scripting & automation
# 2 - data normalization
# 3 - file & database management
# 4 - access control
# 5 - file parsing
# 6 - algorithms


# ----- acknowledgements & disclaimers -----
# 1 - I acknowledge that using proper data management libraries
# would be a better way to go about accomplishing what is shown here.
# however, the aim of this script is to demonstrate a core understanding
# of the aforementioned concepts.

# 2 - without the use of atomic (indivisible) file operations, TOCTOU
# (Time-Of-Check, Time-Of-Use) vulnerabilities can be introduced.
# The potential extent and complexity of file security measures can go far
# beyond the scope of this demonstration. However, I may create another demonstration
# script specifically going into detail about file security.

# 3 - proper logging libraries should be used instead of printing in real-world conditions,
# but too that is beyond the scope of this demonstration.

# read a file, trim trailing & leading whitespaces and newlines, split by newlines
# .strip() is used to avoid \n delimiter introducing blank strings into the output list
def get_file_lines(file_name: str):
    with open(file_name, "r") as file:
        return file.read().strip().split("\n")


# remove all items in removal_list from main_list
def remove_from_list(main_list: list, removal_list: list):
    print(f"Removing {len(removal_list)} items from list... {removal_list}")
    print(f"start: {len(main_list)} items {main_list}")
    items_removed = 0

    # search for and remove entries in removal_list from main_list
    for item in removal_list:
        # for duplicate entries: use a while loop instead of an if statement
        while item in main_list:
            main_list.remove(item)
            items_removed += 1

    print(f"stop:  {len(main_list)} items {main_list}")
    print(f"{items_removed} items successfully removed!")
    separator()


# join a list of strings back into a single string separated by newlines
# write the resulting string to a file
def write_list_to_file(list_: list, filename: str):
    with open(filename, "w") as file:
        file.write("\n".join(list_))
    print(filename, f"saved! ({len(list_)} lines)")
    separator()


# add all items in addition_list to main_list
def add_to_list(main_list: list, addition_list: str):
    print(f"Adding {len(addition_list)} items to list... {addition_list}")
    print(f"start: {len(main_list)} items {main_list}")
    items_added = 0

    for item in addition_list:
        if item not in main_list:
            main_list.append(item)
            items_added += 1

    print(f"stop:  {len(main_list)} items {main_list}")
    print(f"{items_added} items successfully added!")
    separator()


# output the indices of each field name in a list as a dictionary
# used during data normalization
# note: ideally, we would want to use a data management library instead of trying this manually
def get_field_indices(list_: list):
    field_indices = {}
    field_names = list_[0]
    for field_name in field_names:
        field_indices[field_name] = field_names.index(field_name)
    return field_indices


# perform data normalization on parsed log data
# output data as a list of dictionaries
def get_normalized_log_list(log_list: list):
    normalized_list = []
    field_indices = get_field_indices(log_list)

    for line in log_list[1:]:
        normalized_list.append({

            # here, we take a formatted time string that is easy for people to read
            # & convert it into "epoch" time, which is easier for computers to read.
            # note: epoch time is the number of seconds since jan 1 1970. thus you can
            # perform mathematical & conditional operations with it to help
            # implement brute force attack mitigation and more.
            "time": int(datetime.strptime(line[field_indices["time"]], "%Y-%m-%d %H:%M:%S").timestamp()),

            # convert true/false string into boolean datatype
            "success": line[field_indices["success"]] == "true",

            # no normalization needed - already string data
            "user_name": line[field_indices["user_name"]],
            "ip_address": line[field_indices["ip_address"]],

        })

    return normalized_list


# use a class to contain attributes & methods related to logging in
class AuthenticationManager:
    # this many failed login attempts from an IP address within this span of time
    # will block an IP from making any additional login attempts.
    # note: in real-world conditions, this would be loaded from a configuration file.
    limit_login_attempts = 3
    limit_login_interval = 60 * 3

    log_list = []
    allow_list = []

    def update(self, log_list: list, allow_list: list):
        self.log_list = log_list
        self.allow_list = allow_list

    # pretend to log in to simulate an access control system
    # note: in real world conditions, we would want to cache recent log data
    # and keep it in memory. reading the entire log file after every login attempt
    # would introduce a vulnerability to DoS (Denial of Service) attacks.
    def login(self, timestamp: int, username: str, ip_address: str):
        print(f"[{timestamp}] User \"{username}\" attempting login from {ip_address}")

        # check allow list for user's IP address (simulate access control)
        # note: IP addresses can be spoofed by an attacker. this should be just one line of defense
        if ip_address in self.allow_list:
            print(f"{ip_address} is in the allow list!")
        else:
            print(f"{ip_address} is not in the allow list! ACCESS DENIED")
            return

        # check for failed login attempts from this IP within a timespan
        # (simulate brute force attack mitigation)
        # note: in real world conditions, an attacker could use multiple IP addresses
        # to bypass this kind of security control. a firewall can help prevent this
        normalized_log_list = get_normalized_log_list(self.log_list)

        failed_login_attempts = 0

        for data in normalized_log_list:
            if (ip_address == data["ip_address"]
                    and data["success"] is False
                    and timestamp - data["time"] <= self.limit_login_interval):
                failed_login_attempts += 1

        if failed_login_attempts >= self.limit_login_attempts:
            print(f"Too many failed login attempts from {ip_address} - ACCESS DENIED")
            return

        # all checks passed! good to go
        print(f"Access granted! Welcome back, {username}!")


# add separators to improve readability of print output
def separator():
    print("--------------------------------------------------")


def main():
    separator()

    # for consistency's sake, let's assume the script runs at this point in time.
    fake_time = "2026-01-13 16:00:00"
    fake_timestamp = int(datetime.strptime(fake_time, "%Y-%m-%d %H:%M:%S").timestamp())

    # load IP allow list into the script
    # pretend this is actually allow_list.txt
    allow_list = get_file_lines("mock_data/_allow_list_unmodified.txt")

    # load a list of IPs to remove from the allow list
    # remove all IPs in the list from the allow list
    to_remove = get_file_lines("mock_data/ips_to_remove.txt")
    remove_from_list(allow_list, to_remove)

    # load a list of IPs to add to the allow list
    # add all applicable IPs in the list to the allow list
    to_add = get_file_lines("mock_data/ips_to_add.txt")
    add_to_list(allow_list, to_add)

    # save any changes made to the allow list
    write_list_to_file(allow_list, "mock_data/allow_list.txt")

    # load all lines from the log file into the script
    log_lines = get_file_lines("mock_data/login_attempts_2026-01-13.txt")

    # split contents of all login attempt lines at each comma
    log_list = []

    for line in log_lines:
        log_list.append(line.split(","))

    # convert all data in the log list into a normalized format
    normalized_log_list = get_normalized_log_list(log_list)

    # show field names for convenience's sake
    print(log_list[0])

    # examine contents of all data fields in the log
    # use slice notation to avoid iterating through the field names line
    for data in normalized_log_list:
        print(f"{data["time"]} - {data["user_name"]} - {data["ip_address"]} - {data["success"]}")

    separator()

    auth_manager = AuthenticationManager()
    auth_manager.update(log_list, allow_list)

    # fail: IP not in allow list
    auth_manager.login(fake_timestamp - 12, "dave", "120.60.120.60")
    separator()

    # fail: IP recently failed too many login attempts
    auth_manager.login(fake_timestamp - 5, "dave", "195.97.229.41")
    separator()

    # success: IP in allow list & no recent failed logins from this IP
    auth_manager.login(fake_timestamp - 36, "arnold", "100.46.36.241")

    # note: under real-world conditions, you would probably have checks for valid usernames & passwords
    # which would involve keeping track of accounts & having a salted hashed password database.
    # but those are beyond the scope of this demonstration.

    separator()


if __name__ == "__main__":
    main()
