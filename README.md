# Azure ATT&CK Testing Scripts
This repository contains a comprehensive shell script for testing Azure environments against the MITRE ATT&CK framework. The script covers various attack techniques and provides detailed logging and export options for results. Ideal for security professionals looking to assess the security posture of their Azure deployments in a systematic way. Ensure you have the appropriate permissions and use in a controlled environment. Follow all legal and ethical guidelines when conducting security testing.

# Details
This bash script simulates various security assessments for an Azure Virtual Machine (VM) using the Azure CLI. It runs multiple security checks, including scenarios like phishing simulations, drive-by compromises, unauthorized script executions, and more. Here's a breakdown:

### Key Functions:
- **Login and Subscription Setup**: 
  - Logs into Azure using `az login`.
  - Sets the desired subscription for the session with `az account set`.

- **Test Execution**:
  - **Drive-by Compromise**: Looks for suspicious browser processes on the VM.
  - **Unauthorized Script Execution**: Checks for running unauthorized scripts by using process filters.
  - **User Execution of Malicious Code**: Monitors for potential user execution of malicious code using `auditctl`.
  - **Fileless Execution**: Scans for Powershell activity related to fileless malware attacks.
  - **New Account Creation**: Uses Azure AD commands to check for new account creation.
  - **Scheduled Tasks and Services**: Reviews scheduled tasks and services to identify suspicious activities.
  - **Privilege Escalation**: Runs a script to check for vulnerabilities in installed services.
  - **Token Manipulation**: Monitors for possible token manipulation.
  - **Defense Evasion**: Checks for obfuscated files, masquerading, and disabled security tools.
  - **Credential Access**: Simulates brute-force and credential dumping attempts.

### Custom Logging:
- Logs results for each test using the `log_result` function. 
- For each test, the script evaluates the command result (`$?`), outputs it, and logs it into a CSV file (`log.csv`).

### Example Command Usage:
- The script heavily uses Azure CLI's `az vm run-command invoke` to run shell scripts on a specific Azure VM, combined with various tools such as `ps aux`, `auditctl`, and `nmap` to execute and monitor system commands.

### Potential Enhancements:
- **Dynamic Time Filters**: You could make the new account creation date dynamic by calculating the date from the current time.
- **Error Handling**: More detailed error handling could be added to capture Azure CLI errors during command invocations.

# Steps
Here are the steps to run the script:
1. Set up the environment variables:
   - Replace `"your_subscription_id"` with your actual Azure subscription ID.
   - Replace `"your_resource_group"` with the name of the resource group you want to test.
   - Replace `"your_vm_name"` with the name of the virtual machine you want to test.
2. Save the script to a file with a `.sh` extension, for example, `azure_attck_test.sh`.
3. Open a terminal and navigate to the directory where the script is saved.
4. Make the script executable by running: `chmod +x azure_attck_test.sh`.
5. Run the script by typing: `./azure_attck_test.sh`.

During execution, the script will perform various tests on the Azure environment based on the ATT&CK framework. The output will display the results of each test.
Remember to ensure that you have the necessary permissions in Azure as mentioned earlier. Also, be cautious when running these tests in a production environment and consider using a test or staging environment instead.

# Permissions
To run the tests in the provided script and perform an ATT&CK assessment on Azure, the following user permissions are typically required:

**For Azure CLI Commands**:
- `Contributor` or higher role on the subscription or resource group level. This allows running commands like `az vm run-command invoke`, `az account set`, and `az ad user list`.

**For Virtual Machine Access**:
- Permission to connect to and run commands on the virtual machines. This might involve having appropriate access rights such as SSH access for Linux VMs or Remote Desktop access for Windows VMs.

**For Azure Active Directory**:
- Permission to list users (`az ad user list`), which usually requires a role that has read access to Azure Active Directory users.

It's important to note that granting these permissions should be done carefully and following the principle of least privilege. Only grant the necessary permissions for the specific tasks and users performing the security assessment. Additionally, make sure to follow best practices and security guidelines when configuring permissions in Azure to avoid potential security risks.
