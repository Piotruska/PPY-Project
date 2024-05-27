import os
import zipfile
import hashlib
import requests
import time
import logging
import json
import shutil
from pathlib import Path
from PyPDF2 import PdfReader
import re

# Setup logging
logging.basicConfig(filename='log.txt', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

VIRUSTOTAL_API_KEY = 'cb22c177cf5a39cb15051d22831a8d07c2ca491a997a6cc530a17758f1458fec'  # Replace with your actual VirusTotal API key


def get_file_path():
    print("Welcome to the ZIP Security Analysis Tool")
    path = input("Enter the path to the ZIP file: ")
    if not os.path.exists(path):
        raise FileNotFoundError("The specified file does not exist.")
    if not path.endswith('.zip'):
        raise ValueError("The file is not a ZIP file.")
    return path


def requires_password(zip_path):
    with zipfile.ZipFile(zip_path) as zf:
        try:
            zf.extractall(pwd=None, path='unzipped_files')
            return False
        except RuntimeError:
            return True
        except Exception as e:
            logging.error(f"Unexpected error when checking password requirement: {str(e)}")
            raise e


def check_zip_password(zip_path, password_file):
    start_time = time.time()
    with open(password_file, 'r') as file:
        passwords = file.readlines()

    with zipfile.ZipFile(zip_path) as zf:
        for password in passwords:
            try:
                zf.setpassword(password.strip().encode())
                zf.testzip()  # If no exception, password is correct
                duration = time.time() - start_time
                print(f"Password found: {password.strip()}, Time taken: {duration:.2f} seconds")
                logging.info(f"Password found: {password.strip()} in {duration:.2f} seconds")
                return password.strip()
            except RuntimeError:
                continue
    print("Password not found in the list.")
    logging.info("Password not found in the list.")
    return None


def unzip_and_checksum(zip_path, password):
    checksums = {}
    file_list = []
    with zipfile.ZipFile(zip_path) as zf:
        zf.setpassword(password.encode() if password else None)
        try:
            zf.extractall(path='unzipped_files')
            file_list = zf.namelist()
            for file in file_list:
                try:
                    with zf.open(file) as f:
                        data = f.read()
                        checksum = hashlib.sha256(data).hexdigest()
                        checksums[file] = checksum
                except Exception as e:
                    logging.error(f"Error reading file {file} from zip: {str(e)}")
                    continue
            logging.info("Checksums generated for all files.")
        except Exception as e:
            logging.error(f"Error extracting file from zip: {str(e)}")
            raise e
    return file_list, checksums


def virustotal_check(file_hash):
    url = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={VIRUSTOTAL_API_KEY}&resource={file_hash}"
    response = requests.get(url)
    if response.status_code == 200:
        result = response.json()
        positives = result.get('positives', 0)
        total = result.get('total', 0)
        scan_date = result.get('scan_date', 'N/A')
        return f"{positives}/{total} positives (Scan date: {scan_date})"
    else:
        return 'N/A'


def search_keywords(content):
    keywords = ['PESEL', 'password']
    counts = {key: 0 for key in keywords}
    emails = set()
    for keyword in keywords:
        counts[keyword] = len(re.findall(keyword, content, re.IGNORECASE))
    emails.update(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content))
    return {'keywords': counts, 'emails': list(emails)}


def generate_report(checksums, keywords_report, file_list, zip_password):
    report = []
    report.append("FILE STATUS REPORT")
    report.append(f"ZIP Password: {zip_password if zip_password else 'N/A'}\n")
    report.append("{:<40} {:<64} {:<40}".format("File Name", "Checksum (SHA-256)", "VirusTotal Result"))

    for file in file_list:
        virustotal_result = virustotal_check(checksums[file])
        report.append("{:<40} {:<64} {:<40}".format(file, checksums[file], virustotal_result))

    report.append("\n" + "=" * 120 + "\n")
    report.append("KEYWORDS REPORT")
    report.append("\n" + "=" * 120 + "\n")

    for file in file_list:
        if file in keywords_report:
            report.append(f"\n{file}")
            report.append("\n{:<20} {:<10}".format("Keyword", "Occurrence"))
            for keyword, count in keywords_report[file]['keywords'].items():
                report.append("{:<20} {:<10}".format(keyword, count))
            report.append("\nUnique Emails:")
            for email in keywords_report[file]['emails']:
                report.append(f"{email}")
        report.append("\n" + "." * 120 + "\n")

    # Write the report to a text file
    report_path = 'report_summary.txt'
    with open(report_path, 'w') as f:
        f.write("\n".join(report))

    # Generate and save the checksum of the report
    with open(report_path, 'rb') as f:
        report_data = f.read()
        report_checksum = hashlib.sha256(report_data).hexdigest()

    with open('hash.txt', 'w') as hf:
        hf.write(report_checksum)

    logging.info("Report and checksum generated successfully.")
    return report_path, 'hash.txt'


def clean_up(paths):
    for path in paths:
        try:
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        except Exception as e:
            logging.error(f"Error removing {path}: {str(e)}")


def main():
    try:
        zip_path = get_file_path()
        password_file = '10k-most-common.txt'  # Adjust to your path
        password_required = requires_password(zip_path)
        if password_required:
            password = check_zip_password(zip_path, password_file)
            if not password:
                print("Could not open the ZIP file as the password was not found.")
                return
        else:
            password = None

        file_list, checksums = unzip_and_checksum(zip_path, password)

        # Process each file for keywords
        keywords_report = {}
        for file in file_list:
            file_path = os.path.join('unzipped_files', file)
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    # Try to decode the content if it's a text-based file
                    try:
                        text_content = content.decode('utf-8')
                        keywords_report[file] = search_keywords(text_content)
                    except UnicodeDecodeError:
                        if file.endswith('.pdf'):
                            try:
                                reader = PdfReader(file_path)
                                text = ''
                                for page in reader.pages:
                                    page_text = page.extract_text()
                                    if page_text:
                                        text += page_text
                                keywords_report[file] = search_keywords(text)
                            except Exception as e:
                                logging.error(f"Error processing PDF {file}: {str(e)}")
                        # For non-text files, no keyword report is generated
                        keywords_report[file] = {'keywords': {}, 'emails': []}
            except Exception as e:
                logging.error(f"Error reading file {file}: {str(e)}")

        # Debugging: log the full keywords_report
        logging.debug(f"Full keywords report: {json.dumps(keywords_report, indent=2)}")

        # Generate report and obtain checksum
        report_file, hash_file = generate_report(checksums, keywords_report, file_list, password)

        # Repack all items into a new ZIP file
        final_zip_path = os.path.join(os.path.expanduser('~'), 'Downloads', 'Final_Raport.zip')
        try:
            with zipfile.ZipFile(final_zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                for file in file_list:
                    try:
                        full_file_path = os.path.join('unzipped_files', file)
                        if os.path.exists(full_file_path):
                            zf.write(full_file_path, arcname=file)
                        else:
                            logging.error(f"File not found: {full_file_path}")
                    except Exception as e:
                        logging.error(f"Error adding file {file} to zip: {str(e)}")
                zf.write(report_file, arcname='report_summary.txt')
                zf.write(hash_file, arcname='hash.txt')
                zf.write('log.txt', arcname='log.txt')
        except Exception as e:
            logging.error(f"Error creating final zip file: {str(e)}")
            raise e
        print(f"All files re-zipped and stored in {final_zip_path}.")

        # Clean up temporary files and directories
        clean_up([os.path.join('unzipped_files', file) for file in file_list] + [report_file, hash_file, 'log.txt'])
        if os.path.exists('unzipped_files'):
            shutil.rmtree('unzipped_files')

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
