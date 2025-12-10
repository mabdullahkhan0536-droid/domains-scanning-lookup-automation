import requests
import pandas as pd
from datetime import datetime
from tkinter import Tk, filedialog
import os
import time
import re
from tqdm import tqdm

OUTPUT_FILE = "vt_domain_results.xlsx"


def load_keys():
    with open("vt_keys.txt", "r") as f:
        keys = [line.strip() for line in f if line.strip()]
    return keys


def select_file():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Select Domain File",
        filetypes=[("Excel or CSV", "*.xlsx;*.xls;*.csv")]
    )
    root.destroy()
    return file_path


def normalize_date(date_str):
    if not date_str:
        return ""

    match = re.search(r"\d{4}-\d{2}-\d{2}", str(date_str))
    if match:
        return match.group(0)

    try:
        ts = int(date_str)
        return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d')
    except:
        pass

    return str(date_str)


def extract_from_whois(whois_text):

    expiry_patterns = [
        r"Expiry date:\s*(.*)",
        r"Expiration Date:\s*(.*)",
        r"expire-date:\s*(.*)",
        r"Registrar Registration Expiration Date:\s*(.*)",
        r"registry expiry date:\s*(.*)",
        r"paid-till:\s*(.*)"
    ]

    updated_patterns = [
        r"Updated date:\s*(.*)",
        r"Last updated on\s*(.*)",
        r"Last Update:\s*(.*)",
        r"Last Modified:\s*(.*)",
        r"Updated Date:\s*(.*)",
        r"update date:\s*(.*)"
    ]

    expiry = ""
    updated = ""

    for p in expiry_patterns:
        m = re.search(p, whois_text, re.IGNORECASE)
        if m:
            expiry = normalize_date(m.group(1))
            break

    for p in updated_patterns:
        m = re.search(p, whois_text, re.IGNORECASE)
        if m:
            updated = normalize_date(m.group(1))
            break

    return expiry, updated


def vt_request(domain, keys, key_index):
    while key_index < len(keys):

        api_key = keys[key_index]
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 429:
            print(f"\n⚠️ API key {key_index+1} hit rate-limit — switching")
            key_index += 1
            time.sleep(2)
            continue

        if response.status_code != 200:
            print(f"\n❗ Failed {domain}: HTTP {response.status_code}")
            return None, key_index

        data = response.json().get("data", {})
        attrs = data.get("attributes", {})

        malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)

        creation_date = normalize_date(attrs.get("creation_date"))
        last_update = normalize_date(attrs.get("last_update"))
        expire_date = normalize_date(attrs.get("expiration_date"))

        whois_text = attrs.get("whois", "")

        if whois_text:
            whois_expiry, whois_update = extract_from_whois(whois_text)

            if not expire_date:
                expire_date = whois_expiry

            if not last_update:
                last_update = whois_update

        permalink = f"https://www.virustotal.com/gui/domain/{domain}"

        return {
            "domain": domain,
            "malicious_score": malicious,
            "permalink": permalink,
            "creation_date": creation_date,
            "last_update": last_update,
            "expiry_date": expire_date
        }, key_index

    print("\n❗ All API keys exhausted")
    return None, key_index


def append_to_excel(row):
    df_new = pd.DataFrame([row])
    if not os.path.exists(OUTPUT_FILE):
        df_new.to_excel(OUTPUT_FILE, index=False)
    else:
        df_existing = pd.read_excel(OUTPUT_FILE)
        df_combined = pd.concat([df_existing, df_new], ignore_index=True)
        df_combined.to_excel(OUTPUT_FILE, index=False)


def main():
    keys = load_keys()
    key_index = 0
    input_file = select_file()

    ext = os.path.splitext(input_file)[1].lower()
    if ext == ".csv":
        df = pd.read_csv(input_file)
    else:
        df = pd.read_excel(input_file)

    domains = df["domain"].tolist()

    print(f"🔹 Processing {len(domains)} domains…")

    for domain in tqdm(domains, desc="Scanning Domains", unit="domain"):
        info, key_index = vt_request(domain, keys, key_index)
        if info:
            append_to_excel(info)
        if key_index >= len(keys):
            print("\n❗ No remaining API keys — stopping")
            break

    print("\n✅ Completed — results saved continuously.")


if __name__ == "__main__":
    main()
