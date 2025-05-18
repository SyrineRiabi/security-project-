import re
import hashlib
import requests
import math

# Example: hashed versions of "password" and "123456"
HASHED_BLACKLIST = {
    "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",  # "password"
    "7C4A8D09CA3762AF61E59520943DC26494F8941B",  # "123456"
}

#   This function checks whether a given password is in the hashed blacklist.
# It hashes the input password using SHA-1, then compares it to known bad hashes.
# (in our case we used a hashed blacklist rather than a  plain-text blacklist) 
def is_in_hashed_blacklist(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1 in HASHED_BLACKLIST
##########################################################

# helper function to check if the password is breached
def is_password_breached(password):
    # 🔐 Step 1: Hash the password with SHA-1 (securely obfuscates the password)
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # 🧩 Step 2: Split the hash into a prefix (first 5 characters) and a suffix (rest)
    # This supports k-Anonymity: we only send the first 5 chars to the API
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # 🌐 Step 3: Query the Have I Been Pwned API using only the prefix
    # This returns a list of all matching hashes that share this prefix
    url = f"https://api.pwnedpasswords.com/range/{prefix}" #k-anonymity 
    response = requests.get(url)

    # ⚠️ Step 4: Check if the API request was successful
    if response.status_code != 200:
        return False  # We couldn't check, so we assume not breached

    # 📄 Step 5: Parse the response, which returns multiple lines like:
    #   "HASH_SUFFIX:COUNT"
    hashes = (line.split(':') for line in response.text.splitlines())

    # 🔍 Step 6: Check if the suffix of our password's hash matches any returned suffix
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return True  # ✅ The password has been found in a breach

    # ✅ Step 7: If no match is found, the password has not been pwned
    return False

##############################################
def calculate_entropy(password):
    #Calculates the entropy of a given password based on the character sets it uses.
    #Entropy is a measure of how hard a password is to guess (higher = better).
    possible_characters = 0  # This will count the total size of character space used

    # Check for lowercase letters (a–z)
    if any(c.islower() for c in password):
        possible_characters += 26

    # Check for uppercase letters (A–Z)
    if any(c.isupper() for c in password):
        possible_characters += 26

    # Check for digits (0–9)
    if any(c.isdigit() for c in password):
        possible_characters += 10

    # Check for special characters
    if any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
        possible_characters += len("!@#$%^&*(),.?\":{}|<>")  # 21 characters

    # Check for whitespace (e.g., spaces in passphrases)
    if any(c.isspace() for c in password):
        possible_characters += 1

    # Avoid division by zero if no valid characters are found
    if possible_characters == 0:
        return 0

    # Entropy formula: log2(possible_characters) * password_length
    entropy = math.log2(possible_characters) * len(password)

    # Return the result rounded to 2 decimal places
    return round(entropy, 2)
##############################
def estimate_crack_time(entropy, guesses_per_second=1e10):
    #Estimates how long it would take to crack the password by brute-force,
    #based on entropy and an assumed speed of 10 billion guesses per second.
  
    guesses = 2 ** entropy
    seconds = guesses / guesses_per_second

    # Convert to human-readable time
    if seconds < 1:
        return "less than 1 second"
    elif seconds < 60:
        return f"{round(seconds)} seconds"
    elif seconds < 3600:
        return f"{round(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{round(seconds / 3600)} hours"
    elif seconds < 31536000:
        return f"{round(seconds / 86400)} days"
    elif seconds < 31536000 * 100:
        return f"{round(seconds / 31536000)} years"
    else:
        return "centuries or more"
#####################
def check_password_strength(username, password, email=None):
    feedback = []   # 📝 A list to store advice/warnings to return to the user
    score = 0       # 🔢 A score that reflects how strong the password is

    # ✅ Rule 1: Minimum Length
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Password must be at least 12 characters long.")

    # ✅ Rule 2: Contains uppercase letter
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    # ✅ Rule 3: Contains lowercase letter
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    # ✅ Rule 4: Contains number
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Include at least one number.")

    # ✅ Rule 5: Contains special character
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Include at least one special character.")

    # 🚫 Rule 6: Prevent use of username or email (before @) in the password
    if username.lower() in password.lower() or (email and email.lower().split('@')[0] in password.lower()):
        feedback.append("Don't use your username or email in the password.")
    else:
        score += 1

    # 🛑 Rule 7: Check against hashed blacklist of common passwords
    if is_in_hashed_blacklist(password):
        feedback.append("This password is blacklisted (too common).")
    else:
        score += 1

    # 🧠 Rule 8: Passphrase check — if password has 4+ words (each >3 characters)
    if len(password.split()) >= 4 and all(len(word) > 3 for word in password.split()):
        score += 1
        feedback.append("👍 Good! You're using a passphrase.")

    # 🕵️‍♂️ Rule 9: Check if password has been leaked in real data breaches
    if is_password_breached(password):
        feedback.append("⚠️ This password has appeared in a known data breach.")
    else:
        score += 1

    # 🧮 Rule 10: Calculate entropy (randomness) of the password
    entropy = calculate_entropy(password)

    # ⏱️ Estimate how long it would take to crack this password (based on entropy)
    crack_time = estimate_crack_time(entropy)

    # 📊 Add entropy and crack time info to the feedback message
    feedback.append(f"🔐 Entropy: {entropy} bits")
    feedback.append(f"⏱️ Estimated crack time: {crack_time}")

    # 🏁 Final evaluation: classify the score
    if score >= 6:
        return "✅ Strong password!\n" + "\n".join(feedback)
    elif score >= 4:
        return "⚠️ Moderate password.\n Consider improving:\n" + "\n".join(feedback)
    else:
        return "❌ Weak password:\n" + "\n".join(feedback)


# Test your function in the terminal
if __name__ == "__main__":
    while True:
        username = input("Username: ")
        password = input("Password: ")
        print(check_password_strength(username, password))
        print("-" * 40)



