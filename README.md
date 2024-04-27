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

<img src="(https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/2.%20CreatedKeyVault.png)" alt="image-alt-text">

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

<img src="(https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/3.%20DataCollectionRules.png)" alt="image-alt-text">

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

<img src="(https://github.com/Castro-Ian/Project-Azure-Threat-Intelligence/blob/main/Azure%20Threat%20Intelligence%20screenshots/3.5.%20MS%20Sentinel%20Watchlist.png)" alt="image-alt-text">

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

8.5 
