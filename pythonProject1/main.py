import os
import zipfile
import hashlib
import requests
import time
import logging
import json
import shutil
from PyPDF2 import PdfReader
import re
import pyzipper
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from threading import Thread

# Setup logging
logging.basicConfig(filename='log.txt', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

VIRUSTOTAL_API_KEY = 'cb22c177cf5a39cb15051d22831a8d07c2ca491a997a6cc530a17758f1458fec'  # Replace with your actual VirusTotal API key

class ZipSecurityAnalysisTool:
    def __init__(self, master):
        self.master = master
        self.master.title("ZIP Security Analysis Tool")
        self.master.geometry("600x500")
        self.master.configure(bg='#2b2b2b')

        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", background="#ccc")
        self.style.configure("TLabel", background="#2b2b2b", foreground="#ffffff")
        self.style.configure("TEntry", fieldbackground="#4d4d4d", foreground="#000000")
        self.style.configure("TProgressbar", troughcolor="#2b2b2b", background="#4caf50")

        self.label = ttk.Label(master, text="Choose a ZIP file to analyze:")
        self.label.pack(pady=10)

        self.choose_button = ttk.Button(master, text="Choose File", command=self.choose_file)
        self.choose_button.pack(pady=10)

        self.label_keywords = ttk.Label(master, text="Enter keywords to search (separated by commas):")
        self.label_keywords.pack(pady=10)

        self.keywords_entry = ttk.Entry(master, width=50)
        self.keywords_entry.pack(pady=10)
        self.keywords_entry.insert(0, "password,PESEL")

        self.label_password = ttk.Label(master, text="Enter password for the final ZIP file:")
        self.label_password.pack(pady=10)

        self.password_entry = ttk.Entry(master, width=50)
        self.password_entry.pack(pady=10)
        self.password_entry.insert(0, "P4$$w0rd!")

        self.start_button = ttk.Button(master, text="Start Scan", command=self.start_scan_thread, state=tk.DISABLED)
        self.start_button.pack(pady=10)

        self.file_path = ""

    def choose_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        if not self.file_path:
            return

        if not self.file_path.endswith('.zip'):
            messagebox.showerror("Error", "The selected file is not a ZIP file.")
            return

        if not os.path.exists(self.file_path):
            messagebox.showerror("Error", "The specified file does not exist.")
            return

        self.start_button.config(state=tk.NORMAL)
        messagebox.showinfo("File Selected", f"Selected file: {self.file_path}")

    def log_message(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)  # Clear previous message
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.yview(tk.END)
        self.master.update_idletasks()
        time.sleep(1)  # Wait for a second before proceeding

    def start_scan_thread(self):
        self.log_window = tk.Toplevel(self.master)
        self.log_window.title("Scanning...")
        self.log_window.geometry("600x400")
        self.log_window.configure(bg='#2b2b2b')

        self.progress = ttk.Progressbar(self.log_window, orient="horizontal", length=500, mode="indeterminate")
        self.progress.pack(pady=10)

        self.log_text = tk.Text(self.log_window, height=15, state=tk.DISABLED, bg='#4d4d4d', fg='#000000')
        self.log_text.pack(pady=10)

        self.progress.start()
        thread = Thread(target=self.start_scan)
        thread.start()

    def start_scan(self):
        try:
            keywords = self.keywords_entry.get()
            if not keywords:
                keywords = "password,PESEL"
            keywords_list = [kw.strip() for kw in keywords.split(",")]

            password_file = '10k-most-common.txt'  # Adjust to your path
            self.log_message("Starting scan...")

            password_required = requires_password(self.file_path)
            if password_required:
                self.log_message("ZIP file requires a password.")
                password = check_zip_password(self.file_path, password_file)
                if not password:
                    messagebox.showerror("Error", "Could not open the ZIP file as the password was not found.")
                    self.progress.stop()
                    self.log_window.destroy()
                    return
            else:
                password = None

            self.log_message("Unzipping files")
            file_list, checksums = unzip_and_checksum(self.file_path, password)

            keywords_report = {}
            for file in file_list:
                file_path = os.path.join('unzipped_files', file)
                try:
                    logging.info(f"Searching for keywords in file {file_path}")
                    self.log_message(f"Searching for keywords in file {file_path}")
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        try:
                            text_content = content.decode('utf-8')
                            keywords_report[file] = search_keywords(text_content, keywords_list)
                        except UnicodeDecodeError:
                            if file.endswith('.pdf'):
                                try:
                                    reader = PdfReader(file_path)
                                    text = ''
                                    for page in reader.pages:
                                        page_text = page.extract_text()
                                        if page_text:
                                            text += page_text
                                    keywords_report[file] = search_keywords(text, keywords_list)
                                except Exception as e:
                                    logging.error(f"Error processing PDF {file}: {str(e)}")
                                    self.log_message(f"Error processing PDF {file}: {str(e)}")
                            keywords_report[file] = {'keywords': {}, 'emails': []}
                except Exception as e:
                    logging.error(f"Error reading file {file}: {str(e)}")
                    self.log_message(f"Error reading file {file}: {str(e)}")

            logging.debug(f"Full keywords report: {json.dumps(keywords_report, indent=2)}")
            self.log_message(f"Full keywords report: {json.dumps(keywords_report, indent=2)}")

            self.log_message("Generating report...")
            report_file, hash_file = generate_report(checksums, keywords_report, file_list, password)
            logging.debug(f"Generated report file: {report_file}")
            self.log_message(f"Generated report file: {report_file}")
            logging.debug(f"Generated hash file: {hash_file}")
            self.log_message(f"Generated hash file: {hash_file}")

            final_zip_password = self.password_entry.get().encode()

            final_zip_path = os.path.join(os.path.expanduser('~'), 'Downloads', 'Final_Report.zip')

            self.log_message("Creating final encrypted ZIP file...")
            try:
                with pyzipper.AESZipFile(final_zip_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                    zf.setpassword(final_zip_password)
                    logging.info(f"Setting password to {final_zip_password}")
                    self.log_message(f"Setting password to {final_zip_password}")
                    for file in file_list:
                        try:
                            full_file_path = os.path.join('unzipped_files', file)
                            if os.path.exists(full_file_path):
                                zf.write(full_file_path, arcname=file)
                                logging.info(f"Added file to zipped file: {full_file_path}")
                                self.log_message(f"Added file to zipped file: {full_file_path}")
                            else:
                                logging.error(f"File not found: {full_file_path}")
                                self.log_message(f"File not found: {full_file_path}")
                        except Exception as e:
                            logging.error(f"Error adding file {file} to zip: {str(e)}")
                            self.log_message(f"Error adding file {file} to zip: {str(e)}")
                    zf.write(report_file, arcname='report_summary.txt')
                    logging.info(f"Added file to zipped file: {report_file}")
                    self.log_message(f"Added file to zipped file: {report_file}")
                    zf.write(hash_file, arcname='hash.txt')
                    logging.info(f"Added file to zipped file: {hash_file}")
                    self.log_message(f"Added file to zipped file: {hash_file}")
                    zf.write('log.txt', arcname='log.txt')
                    logging.info(f"Added file to zipped file: log.txt")
                    self.log_message(f"Added file to zipped file: log.txt")
            except Exception as e:
                logging.error(f"Error creating final zip file: {str(e)}")
                self.log_message(f"Error creating final zip file: {str(e)}")
                raise e

            messagebox.showinfo("Success", f"All files re-zipped and stored in {final_zip_path}.")
            self.log_message("Scan completed successfully.")

            clean_up([os.path.join('unzipped_files', file) for file in file_list] + [report_file, hash_file, 'log.txt'])
            if os.path.exists('unzipped_files'):
                shutil.rmtree('unzipped_files')
            logging.info(f"Cleaned up unzipped files and created files")
            self.log_message(f"Cleaned up unzipped files and created files")
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            self.log_message(f"An error occurred: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {e}")
        finally:
            self.progress.stop()
            self.log_window.destroy()

def requires_password(zip_path):
    logging.info(f"Checking if {zip_path} needs password")
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
    logging.info(f"Checking passwords for {zip_path} from {password_file}")
    with open(password_file, 'r') as file:
        passwords = file.readlines()

    with zipfile.ZipFile(zip_path) as zf:
        for password in passwords:
            try:
                logging.info(f"Checking password : {password} ")
                zf.setpassword(password.strip().encode())
                zf.testzip()
                duration = time.time() - start_time
                print(f"Password found: {password.strip()}, Time taken: {duration:.2f} seconds")
                logging.info(f"Password found: {password.strip()} in {duration:.2f} seconds")
                return password.strip()
            except RuntimeError:
                logging.error(f"Password is incorrect")
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
            logging.info(f"Extracting all files in zipfile to unzipped_files")
            file_list = zf.namelist()
            for file in file_list:
                try:
                    with zf.open(file) as f:
                        data = f.read()
                        checksum = hashlib.sha256(data).hexdigest()
                        checksums[file] = checksum
                        logging.info(f"Checksums generated for : {file}")
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

def search_keywords(content, keywords):
    counts = {key: 0 for key in keywords}
    emails = set()
    for keyword in keywords:
        logging.info(f"Searching {keyword}")
        counts[keyword] = len(re.findall(keyword, content, re.IGNORECASE))
    logging.info(f"Searching for emails")
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

    report_path = 'report_summary.txt'
    with open(report_path, 'w') as f:
        f.write("\n".join(report))

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

if __name__ == "__main__":
    root = tk.Tk()
    app = ZipSecurityAnalysisTool(root)
    root.mainloop()
