import argparse
import csv
import json
import re

# ---- Regex ----
phone_re = re.compile(r"\d{10}")
aadhaar_re = re.compile(r"\d{12}")
passport_re = re.compile(r"[A-PR-WY]\d{7}", re.I)
upi_re = re.compile(r"[\w.\-]{2,}@\w+")
email_re = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.I)
ipv4_re = re.compile(r"(\d{1,3}\.){3}\d{1,3}")

# ---- Maskers ----
def mask_phone(v): return f"{v[:2]}{'X'*6}{v[-2:]}" if phone_re.fullmatch(v) else "[REDACTED_PHONE]"
def mask_aadhaar(v): return f"XXXX-XXXX-{v[-4:]}" if aadhaar_re.fullmatch(v) else "[REDACTED_AADHAAR]"
def mask_passport(v): return f"{v[0]}{'X'*6}{v[-1]}" if passport_re.fullmatch(v) else "[REDACTED_PASSPORT]"
def mask_upi(v): return f"{v[:2]}XXX@{v.split('@')[1]}" if upi_re.fullmatch(v) else "[REDACTED_UPI]"
def mask_email(v): return f"{v[:2]}XXX@{v.split('@')[1]}" if email_re.fullmatch(v) else "[REDACTED_EMAIL]"
def mask_name(v): return " ".join([p[0] + "X"*(len(p)-1) for p in v.split()])
def mask_address(v): return "[REDACTED_ADDRESS]"
def mask_ip(v): return ".".join(v.split(".")[:2] + ["x","x"]) if ipv4_re.fullmatch(v) else "[REDACTED_IP]"
def mask_device(v): return "[REDACTED_DEVICE]"

# ---- Detect & Redact ----
def detect_and_redact(data):
    redacted = dict(data)
    is_pii = False

    # Standalone PII
    if "phone" in data and phone_re.fullmatch(data["phone"]): 
        redacted["phone"] = mask_phone(data["phone"]); is_pii=True
    if "aadhar" in data and aadhaar_re.fullmatch(data["aadhar"]): 
        redacted["aadhar"] = mask_aadhaar(data["aadhar"]); is_pii=True
    if "passport" in data and passport_re.fullmatch(data["passport"]): 
        redacted["passport"] = mask_passport(data["passport"]); is_pii=True
    if "upi_id" in data and upi_re.fullmatch(data["upi_id"]): 
        redacted["upi_id"] = mask_upi(data["upi_id"]); is_pii=True

    # Combinatorial PII
    comb_count = 0
    name_present = "name" in data and len(data["name"].split())>=2
    email_present = "email" in data and email_re.fullmatch(data["email"])
    address_present = "address" in data
    device_ip_present = ("device_id" in data or "ip_address" in data) and ("name" in data or "customer_id" in data)

    comb_count = sum([name_present, email_present, address_present, device_ip_present])
    if comb_count>=2: 
        is_pii=True
        if name_present: redacted["name"] = mask_name(data["name"])
        if email_present: redacted["email"] = mask_email(data["email"])
        if address_present: redacted["address"] = mask_address(data["address"])
        if device_ip_present:
            if "device_id" in data: redacted["device_id"] = mask_device(data["device_id"])
            if "ip_address" in data: redacted["ip_address"] = mask_ip(data["ip_address"])

    return redacted, is_pii

# ---- Load JSON safely ----
def load_json_safely(s: str):
    s = s.strip()
    try:
        return json.loads(s)
    except Exception:
        pass
    try:
        s2 = s.replace('""', '"')
        return json.loads(s2)
    except Exception:
        pass

# ---- Main ----
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_csv")
    parser.add_argument("--output", default="redacted_output_candidate_full_name.csv")
    args = parser.parse_args()

    with open(args.input_csv, newline='', encoding='utf-8') as fin, \
         open(args.output, 'w', newline='', encoding='utf-8') as fout:

        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=["record_id","redacted_data_json","is_pii"])
        writer.writeheader()

        for row in reader:
            rid = row["record_id"]
            data = load_json_safely(row["data_json"])
            if not isinstance(data, dict):
                writer.writerow({
                    "record_id": rid,
                    "redacted_data_json": json.dumps({"_error":"invalid_json","_raw":row["data_json"]}),
                    "is_pii": False
                })
                continue

            redacted, is_pii = detect_and_redact(data)
            writer.writerow({
                "record_id": rid,
                "redacted_data_json": json.dumps(redacted, ensure_ascii=False),
                "is_pii": is_pii
            })

if __name__ == "__main__":
    main()
