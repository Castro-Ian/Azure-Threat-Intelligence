# Project-Azure-Threat-Intelligence

Azure Threat Intelligence  code pic: <img src="image-url" alt="image-alt-text">
1. The image displays details about an Azure Storage account named "dogstorageaccount". This storage account is a component of Azure's cloud storage service, which provides secure, highly available, and scalable data storage.

Here are the key details shown in the image:

1. Resource Group: The storage account belongs to a resource group named "Rg-SOC".
2. Location: The primary location of the storage account is in the "eastus" region (East US).
3. Primary/Secondary Location: The storage account has geo-redundant replication enabled, with the primary location in East US and the secondary location in West US.
4. Subscription: The storage account is part of the "Azure subscription 1" subscription.
5. Performance: The storage account is configured with the "Standard" performance tier.
6. Replication: The replication type is set to "Read-access geo-redundant storage (RA-GRS)", which means data is replicated to the secondary region and can be read from both locations.
7. Account Kind: The storage account is a "StorageV2 (general purpose v2)" account, which supports all storage services (blobs, files, queues, and tables).
8. Provisioning State: The provisioning of the storage account has "Succeeded".
9. Created: The storage account was created on 3/26/2024 at 7:52:22 PM.
10. Disk State: Both the primary and secondary locations are showing as "Available".

This information provides insights into the configuration, location, replication setup, and overall status of the "dogstorageaccount" Azure Storage account. It helps administrators understand the storage account's properties, geographical redundancy, and operational state within the Azure environment.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/1.%20Created%20Storage%20Account.png" alt="image-alt-text">

/////////////////

2. The image shows the details of a Private Endpoint named "PE-AKV" in the Microsoft Azure environment. A Private Endpoint is a network interface that enables secure, private connectivity from a virtual network to an Azure resource, such as an Azure Key Vault.

Here are the key details displayed:

1. Resource Group: The Private Endpoint belongs to the "RG-SOC" resource group.
2. Location: The Private Endpoint is located in the "East US" region.
3. Subscription: It is part of the "Azure subscription 1" subscription.
4. Virtual Network/Subnet: The Private Endpoint is associated with the "SOC-VNET/default" virtual network and subnet.
5. Network Interface: The network interface used by the Private Endpoint is named "PE-AKV-nic".
6. Private Link Resource: The Azure resource to which the Private Endpoint connects is "LawDogVault", which is likely an Azure Key Vault instance.
7. Target Sub-Resource: The specific sub-resource of the Key Vault that the Private Endpoint connects to is the "vault" resource.
8. Connection Status: The connection status of the Private Endpoint is shown as "Approved".
9. Request/Response: This field is left blank, indicating that no specific request or response data is displayed.

The purpose of this Private Endpoint is to establish a secure, private connection from the "SOC-VNET" virtual network to the "LawDogVault" Azure Key Vault instance. This enables resources within the virtual network to access the Key Vault securely, without exposing it directly to the public internet. Private Endpoints are a critical component of Azure's networking architecture for enhancing security and controlling access to Azure resources.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/2.%20CreatedKeyVault.png" alt="image-alt-text">

////////////

3. The image shows the "Data collection rules" section within the Azure Log Analytics Workspace named "LAW-Dog". This feature allows you to define rules for collecting log data from various sources and routing it to the Log Analytics workspace for analysis, monitoring, and security purposes.
   
In this specific view, there is one data collection rule named "DCR-ALL" configured. Here are the details shown for this rule:

1.	Subscription: The rule is associated with the "Azure subscription 1" subscription.
2.	Resource Group: It belongs to the "RG-SOC" resource group.
3.	Location: The rule is configured for the "East US" region.
4.	Data Sources: The data sources included in this rule are "Windows Event Logs" and "Linux Syslog". This means that the rule is collecting event logs from Windows machines and system logs from Linux machines.
5.	Destinations: The collected log data is being sent to "Azure Monitor Logs", which is the Log Analytics workspace itself.
6.	Kind: The kind of data collection rule is listed as "All", indicating that it is a general-purpose rule for collecting various types of log data.
   
The purpose of this data collection rule is to centralize log data from Windows and Linux systems within the "LAW-Dog" Log Analytics workspace. This allows for unified monitoring, analysis, and security operations across the infrastructure. By collecting and storing log data in Log Analytics, you can leverage various Azure services like Azure Monitor, Azure Sentinel, or custom log analytics solutions to gain insights, detect threats, and proactively manage your Azure environment.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/3.%20DataCollectionRules.png" alt="image-alt-text">    

///////////////

3.5. The image shows the Watchlist feature in Microsoft Sentinel, which is Azure's cloud-native SIEM (Security Information and Event Management) solution. The Watchlist is a crucial component of Sentinel that allows security analysts and administrators to create and manage lists of entities, such as IP addresses, URLs, or file hashes, that are deemed malicious, suspicious, or of interest for security monitoring and investigation purposes.

In this specific view, the following details are displayed:

1. Selected Workspace: The Watchlist is associated with the "law-dog" Log Analytics workspace.
2. Number of Watchlists: There is currently 1 active Watchlist.
3. Total Watchlist Items: The Watchlist contains a total of 55K items or entries.
4. Watchlist Name: The name of the Watchlist is "geoip".
5. Alias: The alias for the Watchlist is also "geoip", which can be used as an alternative reference.
6. Source: The source of the Watchlist items is "geoip-sun", which likely refers to a geographic IP address database or feed.
7. Created and Last Updated: The Watchlist was created and last updated on 3/28/2024.

The Watchlist in Microsoft Sentinel serves as a centralized repository for tracking and monitoring potentially malicious or suspicious entities. Security teams can import data from various sources, such as threat intelligence feeds, internal databases, or manually curated lists, into the Watchlist. Sentinel then correlates incoming log data and security events against the Watchlist entries, enabling efficient threat detection, investigation, and response processes.

In this case, the "geoip" Watchlist is likely used for tracking and monitoring IP addresses based on their geographic locations, which can be helpful in identifying potential threats originating from specific regions or countries.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/3.5.%20MS%20Sentinel%20Watchlist.png" alt="image-alt-text">

//////////////////

4. The image shows the Azure Network Watcher Topology view, which is a feature of the Azure Network Watcher service. Network Watcher is a network performance monitoring and diagnostic tool in Azure that provides visualization and insights into your Azure virtual networks.
   
In this specific image, the Topology view displays a geo map of the world, with a single location pinpointed at East US, which is likely an Azure region where some of your Azure resources are deployed.
The Topology view aims to provide a visual representation of your Azure virtual network resources and their interconnections across different Azure regions. It helps you understand the topology and geographic distribution of your network resources within your Azure subscription.

This particular view shows a very simple topology with only one location pinned on the map, suggesting that your Azure virtual network resources are currently deployed in the East US region. The Topology view can become more complex and insightful as you deploy resources across multiple Azure regions, allowing you to visualize the connectivity and data flows between them.

Overall, this image showcases the Network Watcher Topology feature, which is a valuable tool for Azure administrators and security professionals to gain visibility into their Azure network topology, identify potential connectivity issues, and plan for secure and efficient network architectures.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/4.%20Topology%20East%20US.png" alt="image-alt-text">

///////////////////////////

5. The image shows the "Topology" view within the "Network Watcher" tool, which appears to be part of Microsoft Azure. The topology diagram displays a virtual network (VNet) named "SOC-VNET" that contains a subnet. Within the subnet, there are two connected nodes - one labeled "WEB Subnet" and the other "default".

Based on this network topology visualization, it seems to depict a simple Azure virtual network setup with a single subnet containing two resources, likely virtual machines or other compute instances. This provides a high-level overview of how the virtual networking is structured for this particular Azure subscription and region.

As a cybersecurity specialist, key things I would note are:
1. Ensuring the VNet is properly secured with network security groups and access controls
2. Verifying the individual subnet and resources have appropriate security configurations 
3. Monitoring network traffic to/from the VNet and between the resources for any anomalies
4. Checking that secure connectivity methods are used for any connections into the VNet from outside networks
5. Validating encryption is in place as needed for data in-transit across this network topology

Let me know if you need any other details or have additional questions! Analyzing the architecture and security controls of cloud network setups like this is an important part of the cybersecurity role.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/5.%20External%20Firewall.png" alt="image-alt-text">
///////////////////////////


5.5. This image shows the "Topology" view within the "Network Watcher" tool from Microsoft Azure, similar to the previous image. However, in this case, the topology diagram displays two connected Azure regions - "East US" and "SOC-VNET".

The "SOC-VNET" icon indicates a virtual network (VNet), while the "East US" icon likely represents an Azure region where some resources are deployed.

From a cybersecurity perspective, this topology suggests that the Azure environment spans multiple regions, with the "SSC-VNET" virtual network present in a different region than the resources in "East US". Some key security considerations for this setup would be:

1. Ensuring secure connectivity and communication between the regions, such as using VPN or ExpressRoute for any cross-region connections.
2. Applying consistent security controls and policies across both regions.
3. Monitoring for any unusual traffic or access patterns between the regions that could indicate a security issue.
4. Verifying appropriate data encryption and protection measures for any data being transferred between regions.
5. Checking that region-specific compliance requirements are being met, if applicable.

Multi-region deployments can provide benefits like high availability and geo-redundancy, but it's important to assess and manage the expanded attack surface and potential security risks that come with a more distributed infrastructure. Let me know if you have any other questions!

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/5.%20Soc-Subnet%20VNET.png" alt="image-alt-text">

/////////////////////////////////////
NEEDS REVISION 
6. The provided image shows a more complex network topology within the Microsoft Azure "Network Watcher" tool, spanning multiple Azure regions and virtual networks (VNets).

From the diagram, we can see several interconnected Azure regions, including "SOC-VNET", "AttackVM", "IpConfig", "WindowsVM", "QualysVM", "AttackVM", and others. These regions contain various subnets and virtual machines (VMs).

The VNets are connected to each other, forming a hub-and-spoke network architecture. This allows communication between the different network segments.

From a cybersecurity perspective, some important considerations for this topology would be:

1. Ensuring strict access controls and network segmentation between the different VNets and subnets to enforce least privilege and reduce the blast radius of potential attacks.
2. Monitoring all traffic flows between the connected regions and resources to detect anomalous activities or indications of lateral movement by adversaries.
3. Implementing robust security measures for the "AttackVM" and any other resources that serve as central connection points, as they could be attractive targets.
4. Applying micro-segmentation where applicable to further isolate workloads and limit the potential impact of breaches.
5. Conducting regular security assessments and penetration tests to identify and remediate any vulnerabilities or misconfigurations in the complex network setup.
6. Ensuring logging and visibility across all the distributed components for effective threat detection and response.

Given the scale and complexity of this multi-region topology, it would require careful design, implementation, and ongoing management to maintain a strong security posture. Comprehensive monitoring, incident response plans, and regular security audits would be crucial.

Let me know if you have any other specific questions about securing this type of Azure network architecture!

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/6.%20NSG%20SC-7%20Defense%20in%20Depth.png" alt="image-alt-text">

////////////////////////////////////////

6.5. The image shows the "Resource View" within the "Network Watcher" tool's "Topology" view in Microsoft Azure. This hierarchical view provides a breakdown of the resources within a specific virtual network (VNet).

The VNet shown is named "SOC-VNET" and it contains a subnet called "default". Within the "default" subnet, there is a resource named "PE-Storage", which appears to be a storage account based on the icon.

From a cybersecurity standpoint, the key aspects to consider for this resource view would be:

1. Reviewing the access controls and permissions configured for the "PE-Storage" storage account to ensure only authorized entities can access it.
2. Checking that sensitive data stored in the storage account is properly encrypted at rest.
3. Monitoring access patterns and API calls to the storage account to identify any suspicious activities.
4. Ensuring the storage account is configured to use secure transfer protocols and enforce encryption in transit.
5. Regularly rotating and securing the access keys for the storage account.
6. Implementing network-level controls to limit access to the storage account, such as using service endpoints or private endpoints.

Storage accounts can hold critical data, so it's important to protect them with a defense-in-depth approach involving identity and access management, encryption, monitoring, and secure network configuration. Azure provides various built-in security features for storage, but proper configuration and monitoring are essential.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/6.%20PE-Storage.png" alt="image-alt-text">

//////////////////

7. The image shows the "Resource View" for a specific virtual machine (VM) named "PE-AKV" within the "SOC-VNET" virtual network in Microsoft Azure.

The resource hierarchy indicates that the "SOC-VNET" virtual network contains a subnet called "default", and within that subnet, there is a VM resource named "PE-AKV". The icon suggests that "PE-AKV" is likely an Azure Key Vault resource, which is a secure vault for storing and managing cryptographic keys, certificates, and secrets.

From a cybersecurity perspective, some important considerations for this Azure Key Vault resource would be:

1. Ensuring strict access policies are configured for the Key Vault to limit access to only authorized users, applications, or services.
2. Implementing role-based access control (RBAC) and Azure Active Directory (AD) integration for granular permission management.
3. Enabling logging and monitoring for the Key Vault to track all access attempts, operations, and potential security events.
4. Regularly reviewing and rotating the keys, certificates, and secrets stored in the Key Vault.
5. Using secure methods for accessing and referencing the Key Vault secrets from applications, such as managed identities or Azure AD authentication.
6. Configuring network restrictions, such as firewall rules or virtual network service endpoints, to control access to the Key Vault at the network level.

Azure Key Vault is a critical service for securely managing sensitive information, so it's crucial to follow best practices for access control, monitoring, and operational security. Proper configuration and management of Key Vault permissions, logging, and network settings are essential to prevent unauthorized access and protect the confidentiality of the stored secrets.

Let me know if you have any further questions or if there are any other aspects of the resource view you'd like me to discuss from a security standpoint.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/7.%20PE-KeyVault.png" alt="image-alt-text">

/////////////////////

 8. The image shows the Network Watcher topology view in the Microsoft Azure portal. It displays a resource view of virtual networks (VNets) and virtual machines (VMs) within an Azure subscription and location.

From a cybersecurity perspective, here are a few key observations:

1. Network topology visibility: The Network Watcher provides a visual representation of the network topology, showing the connections and relationships between VNets and VMs. This helps in understanding the network architecture and identifying potential security risks or misconfigurations.

2. Resource inventory: The topology view lists the specific VNets (windowsvm516) and VMs (WindowsVM, ubuntu16, qcomp1, WindowsVM-nic) present in the Azure environment. Maintaining an accurate inventory of resources is crucial for effective security management and monitoring.

3. Network segmentation: The presence of multiple VNets and VMs suggests network segmentation, which is a good security practice. Properly configured network segmentation helps isolate resources, control traffic flow, and limit the blast radius in case of a security incident.

4. Naming conventions: The resource names follow a consistent naming convention, which is important for organization and easier identification of resources. However, from a security standpoint, it's essential to ensure that sensitive information is not inadvertently exposed through resource names.

To further enhance security, it would be important to review the network security group (NSG) rules associated with the VNets and VMs, ensure proper access controls and permissions are in place, and monitor network traffic for any anomalous activities. Regular security assessments and penetration testing can also help identify and remediate potential vulnerabilities in the Azure environment.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/8.%20Windows%20NIC%20card.png" alt="image-alt-text">
/////////////////////////////////////////////

8.5. The image shows the Network Watcher tool in Microsoft Azure, displaying the Topology view of a Virtual Network named "WindowsVM-ip". 

The topology diagram visualizes the network resources and their interconnections. It includes 4 Virtual Machines (VMs): WindowsVM-ip, ipconfigx, windowsvm1516, and WindowsVM-rmtg. These VMs appear to be connected together within the same virtual network.

From a cybersecurity perspective, this topology view provides a useful high-level visualization of the network architecture. It allows a security analyst to quickly understand what resources exist, how they are linked, and potentially identify any unusual connectivity or network segmentation issues.

However, to do a deeper security assessment, additional information would be needed beyond just the topology, such as details on the security groups, access controls, OS/software patch levels, and traffic flows between the VMs. The topology is a good starting point to get an architectural overview before digging into the more granular security configurations.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/8.%20WindowsVM-IP.png" alt="image-alt-text">

//////////////////////////

9.The image shows the Network Watcher tool in Microsoft Azure, this time displaying the Topology view of a Virtual Network named "attackvm434".

The topology diagram depicts the network resources and their connections. It includes 4 Virtual Machines (VMs): attackvm434, AttackVM, AttackVM-nsg, and ipconfigx. These VMs are interconnected within the same virtual network subnet.

From a cybersecurity perspective, the naming of these resources raises some potential red flags. Having VMs with names like "attackvm" suggests these may be resources intentionally set up for offensive security testing, such as penetration testing or red team exercises. 

In a real production environment, VMs should follow a naming convention and not have names overtly implying they are for attacking or hacking purposes. The "nsg" suffix on one VM likely stands for "Network Security Group", which is an Azure firewall resource for controlling traffic to VMs.

So while this topology appears to be for a controlled security testing environment, in an actual customer deployment seeing VM names like this should warrant further investigation to ensure these are authorized resources and not something an attacker has deployed. Analyzing the NSG rules and other security controls in place would be crucial to determine if this setup is secure and compliant with organizational policies.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/9.%20Linux%20NIC%20Card.png" alt="image-alt-text">

///////////////////////

9.5. The image shows the Network Watcher tool in Microsoft Azure, displaying the Topology view of a Virtual Network named "AttackVM-ip".

The topology diagram visualizes the network resources and their interconnections. It includes 4 Virtual Machines (VMs): AttackVM-ip, ipconfigx, attackvm434, and AttackVM-nsg. These VMs appear to be connected together within the same virtual network.

Similar to the previous topology, the naming of these VMs suggests they are likely part of an intentional setup for offensive security testing or hacking exercises, rather than a standard production environment. Names like "AttackVM" and "attackvm434" imply these resources may be used for conducting simulated attacks or penetration testing.

From a cybersecurity best practices perspective, even in a testing environment, it's advisable to use less obvious naming conventions. If an unauthorized party gains access to the network, overtly named "attack" VMs could become prime targets for lateral movement and privilege escalation.

Additionally, it would be important to review the Network Security Group (NSG) configurations attached to these VMs to ensure they have appropriate restrictions in place. Proper network segmentation should be implemented to isolate these "attack" VMs from any sensitive resources or production systems.

In summary, while this setup seems to be for controlled security testing, care should still be taken with naming standards and security controls to reduce risk if the environment were to be compromised. Thorough monitoring and audit logging should also be in place to detect any suspicious activities stemming from these "attack" designated resources.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/9.%20LinuxVM-IP.png" alt="image-alt-text">

///////////////////////

10. The image shows the Network Watcher tool in Microsoft Azure, displaying the Topology view of a Virtual Network named "QualysVM-Netint-97b3".

The topology diagram visualizes the network resources and their interconnections. It includes 3 Virtual Machines (VMs): QualysVM-Netint-97b3, QualysVM, and QualysVM-nsg-97b3, as well as what appears to be a subnet or gateway resource called ipconfigx. These resources are connected within the same virtual network.

As in the previous example, the naming convention used for these VMs suggests they are part of a Qualys security deployment, likely running vulnerability scans, integrity monitoring or compliance checks on the Azure environment.

From a cybersecurity perspective, a few observations and recommendations:

1. Network Segmentation: The Qualys VMs should be properly isolated in a dedicated security subnet, with strict Network Security Group (NSG) rules controlling inbound and outbound access. The Qualys components should have the minimum required connectivity to perform their function.

2. Secure Configuration: The Qualys VMs themselves need to be hardened, patched, and properly configured to prevent them from being compromised. Access should be restricted to authorized security personnel only.

3. Encryption: Any sensitive data collected by the Qualys tools, such as vulnerability details or system configurations, should be encrypted in transit and at rest.

4. Monitoring: In addition to the security monitoring performed by Qualys, the Qualys infrastructure itself should be monitored for any signs of misuse, tampering, or anomalous activity. Alerts should trigger if the Qualys VMs are accessed outside of expected maintenance windows.

5. Naming Convention: While the "Qualys" naming helps identify the purpose of these resources, using more generic names and applying proper resource tagging would be advisable to avoid providing clear attack targets.

In summary, the use of Qualys suggests the organization is taking proactive steps to assess and manage their cloud security posture. However, it's crucial that the Qualys deployment itself adheres to security best practices to prevent it from being subverted by attackers. Regular testing and validation of the Qualys setup, along with well-defined processes around managing and responding to the Qualys findings, are key to maximizing the security benefits it can provide.


<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/10.%20Qualys%20NIC%20Card.png" alt="image-alt-text">


//////////////////////

10.5 The image shows the Network Watcher tool in Microsoft Azure, displaying the Topology view of a Virtual Network named "QualysVM-ip-500".

The topology diagram visualizes the network resources and their interconnections. It includes 4 Virtual Machines (VMs): QualysVM-ip-500, ipconfigx, QualysVM-Netint-9763, and QualysVM-nsg-9763. These VMs appear to be connected within the same virtual network subnet.

From a cybersecurity perspective, the naming of these resources suggests they are related to Qualys, which is a well-known provider of cloud security and compliance solutions. Qualys offers vulnerability management, web application scanning, and other security tools typically used by organizations to assess and monitor their security posture.

The presence of "Qualys" in the VM names implies these resources may be part of a deployment for running Qualys security scans or agents within this Azure environment. This could be part of a routine vulnerability assessment, compliance checks, or ongoing security monitoring process.

However, as a security best practice, it's generally recommended to avoid using overtly descriptive names that reveal the specific security tools in use. If an attacker gains access to the environment, they could potentially target these Qualys-named VMs to attempt to disable or evade the security monitoring.

To further assess the security of this Qualys setup, it would be important to review:

1. Network Security Group (NSG) rules to ensure only required ports and protocols are permitted.
2. Access controls and authentication mechanisms for managing the Qualys VMs.  
3. Data encryption for any sensitive vulnerability/scan result data stored by Qualys.
4. Monitoring and alerting to detect any unusual behavior or potential tampering of the Qualys VMs.

In summary, while the use of Qualys suggests a positive security initiative, care should be taken to properly secure and monitor the Qualys deployment itself following security best practices and the principle of least privilege. The naming convention used also warrants review to avoid providing unnecessary system details to potential attackers.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/10.%20QualysVM-IP.png" alt="image-alt-text">

////////////////////

11. The image shows a data collection rule named "DCR-ALL" within the Microsoft Azure Log Analytics workspace interface. This rule appears to collect data from multiple sources, specifically Windows Event Logs and Linux Syslog, and sends the collected data to two destinations labeled "Azure Monitor Logs".

From a cybersecurity perspective, collecting and centrally aggregating log data from various sources is a crucial practice for effective security monitoring, incident detection, and investigation. By consolidating logs from different systems, such as Windows and Linux, into a centralized repository like Azure Monitor Logs, security teams can gain a comprehensive view of their environment, perform correlation analysis, and identify potential security threats or anomalies.

However, it's important to ensure that appropriate access controls and data protection measures are in place for the collected log data. Only authorized personnel should have access to the log analytics workspace and the sensitive information it may contain. Additionally, the data should be properly secured both in transit and at rest, using encryption and other security best practices to maintain its confidentiality and integrity.

Regular review and fine-tuning of the data collection rules are also recommended to ensure that only relevant and necessary log data is being collected, minimizing noise and storage costs while still providing adequate visibility for security monitoring purposes.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/11.%20Log%20Analytics%20Workspace%20Data%20Sources.png" alt="image-alt-text">

////////////////////////////

12. The image shows an "Add data source" dialog box within the Microsoft Azure Log Analytics workspace interface, specifically for the "DCR-ALL" data collection rule.

The selected data source type is "Windows Event Logs", and the configuration options allow for choosing between using Sentinel (the Microsoft Defender for Cloud built-in connector) or a custom configuration to collect Windows Security events.

If using Sentinel, it aims to collect Windows Security events to avoid unexpected increases in storage costs. The custom option provides more control over which specific event logs are collected.

The dialog box lists several event log categories that can be selected for collection, such as:

1. Application events (System([Level=4 or Level=0]))
2. Security events (System([band(Keywords,13510798882111488)]))
3. Microsoft-Windows-Windows Defender/Operational events (System([EventID=1116 or EventID=1117]))
4. Microsoft-Windows-Windows Firewall With Advanced Security/Firewall events (System([EventID=2003]))

From a cybersecurity perspective, collecting and monitoring these event logs is crucial for detecting and investigating potential security incidents. Windows Security events can provide valuable insights into authentication attempts, access control changes, and other security-related activities. Application and system events can help identify application failures, misconfigurations, or unexpected behavior that may indicate a security issue.

Windows Defender and Firewall events are particularly important for monitoring endpoint security, as they can reveal malware detection, quarantine actions, and changes to firewall rules that could potentially expose the system to threats.

However, it's essential to carefully consider the storage costs associated with collecting a large volume of event logs and to fine-tune the collection settings to strike a balance between having sufficient visibility and managing storage efficiently. Using XPath queries to filter event logs and limit data collection, as mentioned in the dialog box, is a good practice to optimize log collection.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/12.%20LAW-Windows%20Event%20Logs%20Custom.png" alt="image-alt-text">

//////////////////////////

13. The image shows the same "Add data source" dialog box within the Microsoft Azure Log Analytics workspace interface for the "DCR-ALL" data collection rule, but with the "Custom" option selected for collecting Windows Event Logs.

In this custom configuration, the user has more granular control over which specific event log levels and categories are collected. The available options include:

Application logs:
- Critical
- Error
- Warning
- Information
- Verbose

Security logs:
- Audit success
- Audit failure

System logs (no specific levels shown)

Collecting logs at different levels allows for capturing events of varying severity and importance. From a cybersecurity perspective, this customization enables fine-tuning the log collection to prioritize the most critical events while potentially reducing noise and storage costs.

For example, collecting "Critical", "Error", and "Warning" events from the Application logs can help identify significant application issues or potential indicators of compromise. "Information" and "Verbose" logs may provide additional context but might also generate a higher volume of less relevant data.

Similarly, capturing both "Audit success" and "Audit failure" events from the Security logs is crucial for maintaining visibility into successful and failed access attempts, privilege escalation, and other security-related activities.

System logs can contain valuable information about system health, performance, and stability, which may be relevant for identifying potential security issues or misconfigurations.

By carefully selecting the appropriate log levels and categories, organizations can strike a balance between having comprehensive security visibility and managing the associated storage and analysis costs effectively. It's important to regularly review and adjust these settings based on the organization's specific security requirements, risk profile, and available resources. 

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/13.%20LAW%20Windows%20Events%20Logs.png" alt="image-alt-text">

//////////////////////

14. The image shows the "Add data source" dialog box within the Microsoft Azure Log Analytics workspace interface for the "DCR-ALL" data collection rule. In this case, the selected data source type is "Linux Syslog".

The dialog box allows for setting minimum log levels for selected syslog facilities. The available facilities include:

1. LOG_ALERT
2. LOG_AUDIT
3. LOG_AUTH
4. LOG_AUTHPRIV
5. LOG_CLOCK
6. LOG_CRON
7. LOG_DAEMON
8. LOG_FTP
9. LOG_KERN
10. LOG_LOCAL0

For each facility, the minimum log level can be set, with the options being "Not set" or a specific log level such as "LOG_DEBUG", "none", or others (not fully visible in the image).

From a cybersecurity perspective, collecting and monitoring Linux syslogs is crucial for maintaining visibility into the activities and events occurring on Linux-based systems within the organization's environment. Syslogs can provide valuable information about system behavior, user activities, network connections, and potential security incidents.

By setting appropriate minimum log levels for each syslog facility, organizations can control the verbosity and granularity of the collected logs. This allows for focusing on the most relevant and critical events while minimizing noise and storage requirements.

For example, setting a minimum log level of "LOG_DEBUG" for the "LOG_AUTH" facility can help capture detailed authentication-related events, which are essential for detecting unauthorized access attempts, brute-force attacks, or other security breaches.

Similarly, monitoring facilities like "LOG_DAEMON", "LOG_KERN", and "LOG_CRON" can provide insights into system services, kernel-level events, and scheduled job activities, respectively. These logs can help identify system misconfigurations, performance issues, or suspicious behavior that may have security implications.

It's important to regularly review and adjust the syslog collection settings based on the organization's specific security requirements, risk profile, and available resources. Balancing the need for comprehensive logging with the associated storage and analysis costs is crucial for maintaining an effective and efficient security monitoring strategy.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/14.%20Linux%20Syslog.png" alt="image-alt-text"> 

////////////////////

15. The image shows the "Agents" page within the "LAW-Dog" Log Analytics workspace in the Microsoft Azure portal. It provides an overview of the connected agents for both Windows and Linux servers.

According to the information displayed, there is 1 Windows computer connected via the Azure Monitor Windows agent, and 1 Windows computer connected via the Log Analytics Windows agent (legacy). The "See them in Logs" link suggests that more details about these connected computers can be found in the collected logs.

Below the agent information, there is a section prompting the user to set up the new Azure Monitor agent by navigating to the "Data Collection Rules" section.

From a cybersecurity perspective, having visibility into the connected agents is crucial for ensuring that all relevant systems are properly monitored and that their logs are being collected for security analysis. The Azure Monitor and Log Analytics agents play a key role in collecting and forwarding log data from the connected Windows and Linux machines to the Log Analytics workspace.

It's important to ensure that the agents are deployed on all critical systems and are configured to collect the necessary log data for security monitoring purposes. This includes system events, security logs, application logs, and any other relevant data sources.

Regular maintenance and updates of the agents are also essential to ensure compatibility with the latest security features and to address any potential vulnerabilities. Monitoring the health and connectivity of the agents is crucial to avoid any gaps in log collection that could hinder security visibility.

The prompt to set up the new Azure Monitor agent suggests that there might be newer and enhanced capabilities available. Evaluating and potentially transitioning to the new agent could provide additional benefits and improvements in terms of log collection, performance, and security features.

Overall, keeping a close eye on the connected agents, ensuring their proper configuration, and staying up to date with the latest agent versions and capabilities are important aspects of maintaining a robust security monitoring and log management setup within the Azure environment.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/15.%20Monitor%20for%20Windows.png" alt="image-alt-text">

/////////////////////

16. The image shows the "Configure Fusion" step in the Analytics Rule Wizard for Microsoft Sentinel, which is a cloud-native Security Information and Event Management (SIEM) solution provided by Microsoft Azure.

In this step, you can configure the source signals that Microsoft Sentinel's Fusion machine learning model will use to detect multi-stage attacks by identifying combinations of anomalous behaviors and suspicious activities at various stages of the kill chain.

The available sources include Anomalies, various Microsoft Defender products (for Endpoint, Identity, IoT, Office 365, etc.), Azure Sentinel analytics rules, and Microsoft 365 Defender. All of these sources appear to be included by default, with the option to select specific severity levels for each one.

There is also a section to exclude specific detection patterns from Fusion detection if needed, although no patterns are currently excluded in this example.

Overall, this interface allows you to customize which data sources and alert types will be fed into the Fusion detection model, helping to optimize its ability to identify advanced, multi-stage cyber threats targeting your organization's infrastructure and assets.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/16.%20Sentinel%20Fusion%20Rule.png" alt="image-alt-text">

///////////////////

16.5. The image shows the configuration options for an Azure Storage Account named "dogstorageaccount" in the Microsoft Azure portal.

Here are the key details and settings visible:

1. Account kind: StorageV2 (general purpose v2) - This is the latest account type that supports all storage services like Blobs, Files, Queues, Tables, etc.

2. Performance: Standard is selected, which offers consistent and reliable performance at low costs. Premium option provides higher throughput for workloads with heavy usage patterns.

3. Secure transfer required: Enabled, ensuring that only secure connections (HTTPS) can access the storage account.

4. Allow Blob anonymous access: Disabled, preventing anonymous public access to Blob data.

5. Allow storage account key access: Enabled, allowing requests using the account access keys.

6. Other security-related options like shared access signature (SAS) expiry interval and Microsoft Entra authorization are disabled.

7. Minimum TLS version: Not specified, uses the default Azure setting.

The configuration shows some secure defaults like disabling anonymous Blob access and enabling secure transfers. However, enabling account key access may need additional review based on security requirements. Overall, it allows configuring the storage account type, performance, security, and data access settings as per the application needs.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/16.5.%20Allow%20Blob%20storage%20disabled.png" alt="image-alt-text">

///////////////////////

16.7. The image shows the networking configuration settings for an Azure Key Vault resource named "LawDogVault" in the Microsoft Azure portal.

The key security-related settings visible are:

1. Firewalls and virtual networks:
   - "Disable public access" is selected, which blocks all public internet traffic from accessing this Key Vault resource.

2. Exception:
   - "Allow trusted Microsoft services to bypass this firewall" is checked. This setting allows trusted Azure platform services to access the Key Vault, bypassing the firewall rules.
   - However, it's noted that explicit access permissions still need to be granted in the Access Policies section for trusted services to access this Key Vault.

3. Private Endpoint Connections:
   - This section is not shown in the image, but it allows configuring private endpoints for the Key Vault, enabling secure connectivity from virtual networks.

By disabling public access and requiring private endpoints or trusted service exceptions, these networking settings help secure the Azure Key Vault from unauthorized public access. The "trusted services bypass" setting provides a controlled exception for Azure platform services to access the Key Vault for management or integration purposes while still blocking general internet traffic.

Overall, these settings align with security best practices for an Azure Key Vault by restricting network access and enabling secure private connectivity options.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/16.7.%20Disabled%20public%20acces%20to%20key%20vault.png" alt="image-alt-text">

//////////////

17. The image shows the networking configuration settings for an Azure Storage Account named "dogstorageaccount".

Key observations:

1. Public Network Access: The public network access to this storage account has been explicitly disabled. A message prompts creating a private endpoint connection to grant access instead.

2. Firewall Settings: A note mentions that firewall settings restricting access will remain in effect for up to a minute after saving any updated settings.

3. Network Routing: The routing preference is set to "Microsoft network routing" which routes traffic through Microsoft's network for most scenarios. The alternative "Internet routing" option is not selected.

4. Publish Route-Specific Endpoints: This setting is left unchecked, meaning all services within the storage account will use the same networking settings.

From a cybersecurity perspective, these settings align with best practices:

- Disabling public network access and requiring private endpoints enhances security by restricting direct internet access.

- Using Microsoft network routing keeps data transfers within Microsoft's network instead of routing over the public internet.

- The temporary delay in applying firewall changes aims to prevent accidental lockout and disruptions.

Overall, the configuration aims to minimize exposure to public networks and leverage Azure's private networking capabilities for secure data transfers to and from the storage account. Creating private endpoint connections as prompted would further strengthen secure connectivity.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/17.%20SC7.png" alt="image-alt-text">

//////////////////

17.5. The image shows the "Security Policies" section of the Microsoft Defender for Cloud offering in the Azure portal. This page allows you to manage and apply various security standards and benchmarks to your cloud environment.

The key elements visible are:

1. Security Standards: This section lists several predefined security standards and compliance benchmarks that can be assigned. These include:
   - Microsoft Cloud Security Benchmark (Default)
   - NIST SP 800-171 Rev. 2 (Compliance)
   - CIS Microsoft Azure Foundations Benchmarks v2.0.0 and v1.1.0 (Compliance)
   - NIST SP 800-53 Rev. 5 (Compliance, currently assigned at the Management Group level)
   - [Preview] Australian Government ISM PROTECTED (Compliance)

2. Each standard contains a set of security recommendations (e.g., 242 for Microsoft Cloud Security Benchmark) aligned with that particular benchmark or regulation.

3. The toggle switches allow enabling or disabling the application of a specific standard across your cloud environment.

4. Currently, only the "NIST SP 800-53 Rev. 5" standard is enabled, and it appears to be applied at the Management Group level.

Applying these security standards and benchmarks helps ensure compliance with industry regulations and best practices for secure cloud configurations. Selecting the appropriate standards aligns your Azure environment with the required security controls and policies based on your organization's needs and regulatory requirements.

Overall, this interface provides a centralized way to manage and enforce security baselines consistently across your Azure resources, helping to maintain a secure and compliant cloud posture.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/17.5%20Security%20Policy%20Screenshot%20Microsoft%20Defender.png" alt="image-alt-text">

/////////////////

18. The image appears to be a screenshot from the Microsoft Azure portal, specifically the "Create a private endpoint" section for a storage account named "dogstorageaccount". This section allows you to configure network access and DNS settings for the private endpoint.

From a cybersecurity perspective, a few key points can be observed:

1. Private Endpoints: The ability to create a private endpoint is a security feature that allows you to securely connect to Azure resources (in this case, a storage account) from within your virtual network, without exposing the resource to the public internet. This reduces the attack surface by eliminating direct exposure to the public internet.

2. DNS Integration: The image shows options for integrating the private endpoint with a private DNS zone or using your own DNS servers/host files. Properly configuring DNS is crucial for secure name resolution and avoiding potential DNS rebinding attacks.

3. Virtual Network Isolation: By using a private endpoint within a virtual network, the storage account traffic is isolated from the public internet, mitigating the risk of unauthorized access or data exfiltration.

4. Subscription and Resource Group: The subscription and resource group details are shown, indicating the scope and organization of the Azure resources being configured.

Overall, the use of private endpoints and proper DNS configuration can enhance the security posture of Azure resources by reducing exposure to the public internet and providing a more controlled network access pattern.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/18.%20Private%20DNS.png" alt="image-alt-text">

/////////////////

19. The image shows a concerning security configuration in the Microsoft Azure portal. There is a network security group (NSG) named "AttackVM-nsg" with an inbound security rule "DANGERAllowAnyCustomAnyInbound" that appears to allow any source on any port using any protocol to access the associated resources.

This kind of overly permissive inbound rule essentially opens up the resources associated with this NSG to potential attacks from any source on the internet, which is an extremely risky security practice. It negates the purpose of using network security groups to control and restrict access.

Some specific security concerns with this configuration:

1. Open to attacks: By allowing "Any" source, port, and protocol, this rule exposes the resources to potential malicious traffic, unauthorized access attempts, and various cyber attacks like port scanning, brute-force attacks, and exploitation of vulnerabilities.

2. Lack of restrictions: Best security practices dictate allowing only the minimum required network access by explicitly defining allowed IP addresses, port ranges, and protocols based on legitimate business needs.

3. Risk of data exposure: Depending on the type of resources associated with this NSG, this overly permissive rule could lead to unauthorized access and potential data exfiltration or compromise.

4. Naming convention: The naming of the rule as "DANGERAllowAny..." suggests it may have been created for testing purposes but was inadvertently left in production, which is a security risk.

It is strongly recommended to review and remediate this security rule immediately by either removing it entirely or replacing it with properly restricted and secure inbound rules that align with security best practices and the principle of least privilege.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/19.%20Attack%20VM%20Firewall%20Honey%20Net.png" alt="image-alt-text">

////////////////////

20. The image shows another extremely concerning security configuration within the Microsoft Azure portal. There is a network security group named "WindowsVM-nsg" that has an inbound security rule called "DANGERAllowAnyCustomAnyInbound" with the highest priority (100). This rule allows any source from any port using any protocol to access resources associated with this network security group.

This overly permissive inbound rule essentially exposes the associated resources to potential attacks from any source on the internet, presenting a significant security risk. Some specific security concerns are:

1. Unrestricted access: By allowing "Any" source, port, and protocol, this rule opens up the resources to unauthorized access attempts, exploitation of vulnerabilities, and various cyber threats like port scanning, brute-force attacks, and remote code execution.

2. Highest priority: With a priority of 100, this rule takes precedence over any other inbound rules, making it extremely difficult to restrict access through other rules.

3. Lack of principle of least privilege: This rule violates the security principle of least privilege by granting unrestricted access instead of explicitly allowing only the minimum required access based on legitimate business needs.

4. Potential data exposure: Depending on the type of resources associated with this NSG, this rule could lead to unauthorized access and potential data exfiltration or compromise.

5. Naming convention: The naming convention "DANGERAllowAny..." suggests this rule may have been created for testing purposes but was inadvertently left in production, which is a critical security oversight.

It is strongly recommended to review and remediate this security rule immediately by either removing it entirely or replacing it with properly restricted and secure inbound rules that align with security best practices and the principle of least privilege. Leaving such an overly permissive rule in place significantly increases the risk of successful cyber attacks and data breaches.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/20.%20Windows%20VM%20Firewall%20RuleHoney%20Net%20Screenshot.png" alt="image-alt-text">

///////////////////////////

21. The image shows the Analytics section of Microsoft Sentinel, which is a cloud-native security information and event management (SIEM) solution. Specifically, it displays the list of active detection rules configured within the selected workspace.

From a cybersecurity perspective, a few key observations can be made:

1. Rule Coverage: The rules cover a wide range of security threats, including advanced multi-stage attacks, brute-force attempts, privilege escalation, malware detection, lateral movement, and more. This comprehensive coverage helps detect and respond to various attack vectors and techniques.

2. Severity Levels: The rules are categorized based on severity levels - High, Medium, and Low. High severity rules focus on critical threats like brute-force attacks, privilege escalation, and malware, which aligns with security best practices of prioritizing high-risk threats.

3. Custom Rules: Many of the rules are marked as "CUSTOM," indicating they are tailored to the specific environment or requirements. This allows for better detection of threats specific to the organization's assets and security posture.

4. Rule Types: The rules are a combination of scheduled rules (periodically evaluating conditions) and fusion rules (correlating multiple data sources). This hybrid approach enhances detection capabilities by leveraging different rule types.

5. Tactics and Techniques: The rules are mapped to specific tactics and techniques from the MITRE ATT&CK framework, a widely recognized knowledge base of adversary tactics and techniques. This mapping helps understand the potential attack vectors and facilitate effective response and mitigation.

6. Source Names: Some rules are sourced from the "Gallery Content," which likely refers to pre-built rules provided by Microsoft, while others are "Custom Content," suggesting they are custom-built rules specific to the organization's needs.

Overall, the image showcases a well-configured Microsoft Sentinel deployment with a comprehensive set of detection rules covering various security threats and tailored to the organization's specific requirements. This proactive approach to security monitoring and threat detection is essential for maintaining a robust cybersecurity posture.

<img src="https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/21.%20Sentinel%20Analytics%20Incidents%20(SIEM).png" alt="image-alt-text">

////////////////////
