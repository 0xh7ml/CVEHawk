#! /usr/bin/python3

import json
import argparse
from colorama import Fore
import subprocess
import asyncio
import aiohttp
import re

# Constants & URLs
ghPocURL = "https://poc-in-github.motikan2010.net/api/v1/?cve_id" # GitHub PoC API URL
exploitDBGitLabUrl = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv" # Exploit DB GitLab URL
exploitDownloadURL = "https://www.exploit-db.com/download/"  # Base URL for exploit downloads
inTheWildAPI = "https://inthewild.io/api/exploits"  # Intezer InTheWild API URL

# Run shell commands asynchronously
async def run_command(command):
    """
    Run a shell command asynchronously.
    :param command: The shell command to run.
    :return: The output of the command.
    """
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise Exception(f"Command failed: {stderr.decode().strip()}")
    return stdout.decode()

# Write data to a file
def write_to_file(data, file_name):
    """
    Write data to a file.
    :param data: The data to write to the file.
    :param file_name: The name of the file to write the data to.
    """
    try:
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(data)
    
    except Exception as e:
        print(f"{Fore.RED}[!] Error writing data to file: {e} {Fore.RESET}")

# Fetch PoCs from GitHub
async def fetch_gh_poc(cve_id: str, session: aiohttp.ClientSession):
    """
    Fetch PoC exploits for a given CVE ID from GitHub.
    :param cve_id: The CVE ID for which to fetch PoC exploits.
    :param session: The aiohttp ClientSession object to use for the HTTP request.
    :return: A dictionary containing the source, title, and list of PoC URLs if exploits are found.
    None if no exploits are found or an error occurs.
    """
    try:
        async with session.get(ghPocURL, params={"cve_id": cve_id}) as res:
            data = await res.json()
            if data["pocs"]:
                poc_urls = [poc["html_url"] for poc in data["pocs"]]
                return {
                    "source": "GitHub",
                    "title": f"Exploits for {cve_id}",
                    "urls": poc_urls
                }
            else:
                return None
    except aiohttp.ClientError as e:
        print(f"{Fore.RED}[!] Error fetching Other Sources PoC: {e} {Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error fetching Other Sources PoC: {e} {Fore.RESET}")
    
    return None

# Fetch PoCs from Exploit DB
async def fetch_exploitdb_poc(cve_id: str, session: aiohttp.ClientSession):
    """
    Fetch PoC exploits for a given CVE ID from Exploit DB.
    :param cve_id: The CVE ID for which to fetch PoC exploits.
    :param session: The aiohttp ClientSession object to use for the HTTP request.
    :return: A dictionary containing the source, title, and list of PoC URLs if exploits are found.
    None if no exploits are found or an error occurs.
    """
    try:
        # Fetch the exploits CSV file using the shared session
        async with session.get(exploitDBGitLabUrl, timeout=10) as res:
            data = await res.text()
            write_to_file(data, "files_exploits.csv")
        
        # Run the shell command to extract IDs
        result = await run_command(f"cat files_exploits.csv | grep {cve_id} | cut -d ',' -f1")
        
        # Split the result into a list and remove empty strings
        ids = [id.strip() for id in result.split("\n") if id.strip()]
        
        # Create the list of Exploit URLs
        exploit_urls = [f"{exploitDownloadURL}{id}" for id in ids]
        
        # Return the result dictionary
        if exploit_urls:
            return {
                "source": "Exploit DB",
                "title": f"Exploits for {cve_id}",
                "urls": exploit_urls
            }
        else:
            return None
    
    except aiohttp.ClientError as e:
        print(f"{Fore.RED}[!] Error fetching Other Sources PoC: {e} {Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error fetching Other Sources PoC: {e} {Fore.RESET}")

# Fetch PoCs from Other Sources (Asynchronous)
async def fetch_other_sources_poc(cve_id: str, session: aiohttp.ClientSession):
    """
    Fetch report URLs for a given CVE ID from the API and filter out GitHub URLs using regex.
    :param cve_id: The CVE ID to search for (e.g., 'CVE-2021-44228').
    :param session: The aiohttp ClientSession object to use for the HTTP request.
    :return: A dictionary containing the source, title, and list of filtered report URLs.
    None if no URLs are found or an error occurs.
    """
    try:
        # Fetch data from the API using the shared session
        async with session.get(inTheWildAPI, params={"query": cve_id}) as res:
            res.raise_for_status()  # Raise an exception for HTTP errors
            data = await res.json()
        
        # Define a regex pattern to match GitHub URLs
        github_pattern = re.compile(r"^https://github\.com")
        
        # Extract and filter report URLs using regex
        report_urls = [
            item["reportURL"] for item in data
            if not github_pattern.match(item["reportURL"])  # Exclude GitHub URLs
        ]
        
        # Return the result dictionary
        if report_urls:
            return {
                "source": "Others",
                "title": f"Exploits for {cve_id}",
                "urls": report_urls
            }
        else:
            return None
    
    except aiohttp.ClientError as e:
        print(f"{Fore.RED}[!] Error fetching Other Sources PoC: {e} {Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error fetching Other Sources PoC: {e} {Fore.RESET}")
    
    return None

# Main function
async def main(cve_id: str):
    result = {
        "CVE": cve_id,
        "PoCs": []
    }
    
    # Use a single session for all HTTP requests
    async with aiohttp.ClientSession() as session:
        # Run all fetch functions concurrently
        gh_poc_task = asyncio.create_task(fetch_gh_poc(cve_id, session))
        exploitdb_poc_task = asyncio.create_task(fetch_exploitdb_poc(cve_id, session))
        other_sources_poc_task = asyncio.create_task(fetch_other_sources_poc(cve_id, session))
        
        # Wait for all tasks to complete
        gh_poc, exploitdb_poc, other_sources_poc = await asyncio.gather(
            gh_poc_task,
            exploitdb_poc_task,
            other_sources_poc_task
        )
        
        # Update the result dictionary
        if gh_poc:
            result["PoCs"].append(gh_poc)
        if exploitdb_poc:
            result["PoCs"].append(exploitdb_poc)
        if other_sources_poc:
            result["PoCs"].append(other_sources_poc)
    
    # Print the final result as JSON
    if result != []:
        print(json.dumps(result, indent=4))
    else:
        print(f"{Fore.RED}[!] No PoC exploits found for {cve_id} {Fore.RESET}")

# Banner
def banner(cve_id: str):

    print(Fore.RED+r"""
____ _  _ ____ _  _ ____ _ _ _ _  _ 
|    |  | |___ |__| |__| | | | |_/  
|___  \/  |___ |  | |  | |_|_| | \_ 
                                    
    """+Fore.RESET)
    
    # Initial Request
    print(f"{Fore.GREEN}[*] Fetching PoC's for CVE: {cve_id} {Fore.RESET}")

if __name__ == "__main__":
    # Argument Parser
    arg_parser = argparse.ArgumentParser(description="CVE PoC Finder")
    arg_parser.add_argument("-c", "--cve", help="input target cve id", required=True, type=str, metavar="")
    arg_parser.add_argument("--silent", help="silent mode", required=False, action="store_true")
    args = arg_parser.parse_args()

    # Pass the CVE ID into lowercase
    cve_id = args.cve.upper()

    # Banner Display
    if not args.silent:
        banner(cve_id)
    
    # Run the main function
    asyncio.run(main(cve_id))