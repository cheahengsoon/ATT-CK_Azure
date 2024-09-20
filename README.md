# Azure ATT&CK Testing Scripts
This repository contains a comprehensive shell script for testing Azure environments against the MITRE ATT&CK framework. The script covers various attack techniques and provides detailed logging and export options for results. Ideal for security professionals looking to assess the security posture of their Azure deployments in a systematic way. Ensure you have the appropriate permissions and use in a controlled environment. Follow all legal and ethical guidelines when conducting security testing.

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
