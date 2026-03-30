package compliance

// SOC2Controls defines the Trust Services Criteria controls relevant to KMS operations.
var SOC2Controls = []Control{
	{
		ID: "SOC2-CC6.1", Framework: SOC2TypeII, Category: "Logical and Physical Access",
		Title: "Encryption of Data at Rest", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
	},
	{
		ID: "SOC2-CC6.3", Framework: SOC2TypeII, Category: "Logical and Physical Access",
		Title: "Role-Based Access Control", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles and responsibilities.",
	},
	{
		ID: "SOC2-CC6.6", Framework: SOC2TypeII, Category: "Logical and Physical Access",
		Title: "Encryption in Transit", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
	},
	{
		ID: "SOC2-CC6.7", Framework: SOC2TypeII, Category: "Logical and Physical Access",
		Title: "Transmission Security", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "The entity restricts the transmission, movement, and removal of information to authorized internal and external users.",
	},
	{
		ID: "SOC2-CC7.1", Framework: SOC2TypeII, Category: "System Operations",
		Title: "Security Monitoring", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "The entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.",
	},
	{
		ID: "SOC2-CC7.2", Framework: SOC2TypeII, Category: "System Operations",
		Title: "Anomaly Detection", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "The entity monitors system components and the operation of those components for anomalies indicative of malicious acts or natural disasters.",
	},
	{
		ID: "SOC2-CC7.3", Framework: SOC2TypeII, Category: "System Operations",
		Title: "Incident Response Evaluation", Severity: SeverityHigh, AutomationLevel: AutomationPartial,
		Description: "The entity evaluates security events to determine whether they could or have resulted in a failure to meet objectives.",
	},
	{
		ID: "SOC2-CC7.4", Framework: SOC2TypeII, Category: "System Operations",
		Title: "Incident Response Execution", Severity: SeverityHigh, AutomationLevel: AutomationPartial,
		Description: "The entity responds to identified security incidents by executing a defined incident response program.",
	},
	{
		ID: "SOC2-CC8.1", Framework: SOC2TypeII, Category: "Change Management",
		Title: "Key Lifecycle Management", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure and software.",
	},
	{
		ID: "SOC2-CC9.1", Framework: SOC2TypeII, Category: "Risk Mitigation",
		Title: "Backup and Recovery", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
	},
}

// PCIDSS4Controls defines PCI DSS 4.0 requirements applicable to cryptographic key management.
var PCIDSS4Controls = []Control{
	{
		ID: "PCI-3.5", Framework: PCIDSS4, Category: "Protect Stored Account Data",
		Title: "Protect Stored Cryptographic Keys", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Cryptographic keys used to protect stored account data are secured against disclosure and misuse.",
	},
	{
		ID: "PCI-3.6", Framework: PCIDSS4, Category: "Protect Stored Account Data",
		Title: "Key Management Procedures", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Cryptographic key management processes and procedures are defined and implemented for cryptographic keys used to protect stored data.",
	},
	{
		ID: "PCI-3.7", Framework: PCIDSS4, Category: "Protect Stored Account Data",
		Title: "Key Rotation Policies", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Where cryptography is used to protect stored account data, key management processes cover all aspects of the key lifecycle.",
	},
	{
		ID: "PCI-4.1", Framework: PCIDSS4, Category: "Encrypt Transmission",
		Title: "Strong Cryptography for Transmission", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Strong cryptography and security protocols are implemented to safeguard sensitive cardholder data during transmission over open, public networks.",
	},
	{
		ID: "PCI-4.2", Framework: PCIDSS4, Category: "Encrypt Transmission",
		Title: "Secure Messaging", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "PAN is secured with strong cryptography whenever it is sent via end-user messaging technologies.",
	},
	{
		ID: "PCI-7.1", Framework: PCIDSS4, Category: "Restrict Access",
		Title: "Least Privilege Access", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Access to system components and cardholder data is limited to only those individuals whose job requires such access.",
	},
	{
		ID: "PCI-7.2", Framework: PCIDSS4, Category: "Restrict Access",
		Title: "Access Control Systems", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "An access control system is established for systems components that restricts access based on a user's need to know.",
	},
	{
		ID: "PCI-8.3", Framework: PCIDSS4, Category: "Identify Users and Authenticate",
		Title: "Multi-Factor Authentication", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Multi-factor authentication is implemented to secure access into the CDE for all personnel with administrative access.",
	},
	{
		ID: "PCI-8.4", Framework: PCIDSS4, Category: "Identify Users and Authenticate",
		Title: "MFA for Remote Access", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Multi-factor authentication is implemented for all remote network access originating from outside the entity's network.",
	},
	{
		ID: "PCI-10.1", Framework: PCIDSS4, Category: "Log and Monitor",
		Title: "Audit Trail Logging", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Audit trails are implemented to link all access to system components to each individual user.",
	},
	{
		ID: "PCI-10.2", Framework: PCIDSS4, Category: "Log and Monitor",
		Title: "Automated Audit Trails", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Automated audit trails are implemented for all system components to reconstruct security-relevant events.",
	},
	{
		ID: "PCI-10.3", Framework: PCIDSS4, Category: "Log and Monitor",
		Title: "Audit Trail Protection", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Audit trails are protected from unauthorized modification.",
	},
	{
		ID: "PCI-12.10", Framework: PCIDSS4, Category: "Organizational Policies",
		Title: "Incident Response Plan", Severity: SeverityHigh, AutomationLevel: AutomationPartial,
		Description: "An incident response plan exists and is ready to be activated immediately in the event of a security breach.",
	},
}

// ISO27001Controls defines ISO/IEC 27001 Annex A controls relevant to KMS.
var ISO27001Controls = []Control{
	{
		ID: "ISO-A.10.1", Framework: ISO27001, Category: "Cryptography",
		Title: "Policy on Use of Cryptographic Controls", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "A policy on the use of cryptographic controls for protection of information shall be developed and implemented.",
	},
	{
		ID: "ISO-A.10.2", Framework: ISO27001, Category: "Cryptography",
		Title: "Key Management", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "A policy on the use, protection, and lifetime of cryptographic keys shall be developed and implemented through their whole lifecycle.",
	},
	{
		ID: "ISO-A.9.1", Framework: ISO27001, Category: "Access Control",
		Title: "Access Control Policy", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "An access control policy shall be established, documented, and reviewed based on business and information security requirements.",
	},
	{
		ID: "ISO-A.9.2", Framework: ISO27001, Category: "Access Control",
		Title: "User Access Management", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "A formal user access provisioning process shall be implemented to assign or revoke access rights for all user types to all systems and services.",
	},
	{
		ID: "ISO-A.9.4", Framework: ISO27001, Category: "Access Control",
		Title: "System and Application Access Control", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Access to systems and applications shall be controlled by a secure log-on procedure including multi-factor authentication.",
	},
	{
		ID: "ISO-A.12.3", Framework: ISO27001, Category: "Operations Security",
		Title: "Information Backup", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Backup copies of information, software, and system images shall be taken and tested regularly in accordance with an agreed backup policy.",
	},
	{
		ID: "ISO-A.12.4", Framework: ISO27001, Category: "Operations Security",
		Title: "Logging and Monitoring", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Event logs recording user activities, exceptions, faults, and information security events shall be produced, kept, and regularly reviewed.",
	},
	{
		ID: "ISO-A.13.1", Framework: ISO27001, Category: "Communications Security",
		Title: "Network Security Management", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Networks shall be managed and controlled to protect information in systems and applications, including data in transit.",
	},
	{
		ID: "ISO-A.16.1", Framework: ISO27001, Category: "Incident Management",
		Title: "Information Security Incident Management", Severity: SeverityHigh, AutomationLevel: AutomationPartial,
		Description: "Management responsibilities and procedures shall be established to ensure a quick, effective, and orderly response to information security incidents.",
	},
	{
		ID: "ISO-A.17.1", Framework: ISO27001, Category: "Business Continuity",
		Title: "Information Security Continuity", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Information security continuity shall be embedded in the organization's business continuity management systems.",
	},
}

// FedRAMPControls defines FedRAMP Moderate baseline controls relevant to KMS.
var FedRAMPControls = []Control{
	{
		ID: "FEDRAMP-SC-12", Framework: FedRAMPModerate, Category: "System and Communications Protection",
		Title: "Cryptographic Key Establishment and Management", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "The information system establishes and manages cryptographic keys for required cryptography using NIST-compliant key management technology and processes.",
	},
	{
		ID: "FEDRAMP-SC-13", Framework: FedRAMPModerate, Category: "System and Communications Protection",
		Title: "Cryptographic Protection", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "The information system implements FIPS-validated cryptography in accordance with applicable federal laws, orders, directives, policies, and regulations.",
	},
	{
		ID: "FEDRAMP-SC-8", Framework: FedRAMPModerate, Category: "System and Communications Protection",
		Title: "Transmission Confidentiality and Integrity", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "The information system protects the confidentiality and integrity of transmitted information using TLS 1.3 or equivalent.",
	},
	{
		ID: "FEDRAMP-SC-28", Framework: FedRAMPModerate, Category: "System and Communications Protection",
		Title: "Protection of Information at Rest", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "The information system protects the confidentiality and integrity of information at rest using FIPS-validated encryption.",
	},
	{
		ID: "FEDRAMP-AC-2", Framework: FedRAMPModerate, Category: "Access Control",
		Title: "Account Management", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "The organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
	},
	{
		ID: "FEDRAMP-AC-6", Framework: FedRAMPModerate, Category: "Access Control",
		Title: "Least Privilege", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "The organization employs the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned tasks.",
	},
	{
		ID: "FEDRAMP-IA-2", Framework: FedRAMPModerate, Category: "Identification and Authentication",
		Title: "Identification and Authentication (Organizational Users)", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "The information system uniquely identifies and authenticates organizational users using multi-factor authentication.",
	},
	{
		ID: "FEDRAMP-IA-5", Framework: FedRAMPModerate, Category: "Identification and Authentication",
		Title: "Authenticator Management", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "The organization manages information system authenticators by verifying the identity of the individual as part of the initial authenticator distribution.",
	},
	{
		ID: "FEDRAMP-AU-2", Framework: FedRAMPModerate, Category: "Audit and Accountability",
		Title: "Audit Events", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "The organization determines that the information system is capable of auditing all security-relevant events.",
	},
	{
		ID: "FEDRAMP-AU-3", Framework: FedRAMPModerate, Category: "Audit and Accountability",
		Title: "Content of Audit Records", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "The information system generates audit records containing sufficient information to establish what type of event occurred, when, where, the source, and the outcome.",
	},
	{
		ID: "FEDRAMP-AU-6", Framework: FedRAMPModerate, Category: "Audit and Accountability",
		Title: "Audit Review, Analysis, and Reporting", Severity: SeverityHigh, AutomationLevel: AutomationPartial,
		Description: "The organization reviews and analyzes information system audit records for indications of inappropriate or unusual activity.",
	},
	{
		ID: "FEDRAMP-CP-9", Framework: FedRAMPModerate, Category: "Contingency Planning",
		Title: "Information System Backup", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "The organization conducts backups of user-level and system-level information contained in the information system at a defined frequency.",
	},
	{
		ID: "FEDRAMP-CP-10", Framework: FedRAMPModerate, Category: "Contingency Planning",
		Title: "Information System Recovery and Reconstitution", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "The organization provides for the recovery and reconstitution of the information system to a known state after a disruption.",
	},
	{
		ID: "FEDRAMP-IR-4", Framework: FedRAMPModerate, Category: "Incident Response",
		Title: "Incident Handling", Severity: SeverityHigh, AutomationLevel: AutomationPartial,
		Description: "The organization implements an incident handling capability for security incidents that includes preparation, detection, analysis, containment, eradication, and recovery.",
	},
	{
		ID: "FEDRAMP-IR-8", Framework: FedRAMPModerate, Category: "Incident Response",
		Title: "Incident Response Plan", Severity: SeverityHigh, AutomationLevel: AutomationPartial,
		Description: "The organization develops an incident response plan that provides the organization with a roadmap for implementing its incident response capability.",
	},
}

// HIPAAControls defines HIPAA Security Rule controls relevant to KMS.
var HIPAAControls = []Control{
	{
		ID: "HIPAA-164.312(a)(2)(iv)", Framework: HIPAA, Category: "Technical Safeguards",
		Title: "Encryption and Decryption", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Implement a mechanism to encrypt and decrypt electronic protected health information.",
	},
	{
		ID: "HIPAA-164.312(e)(2)(ii)", Framework: HIPAA, Category: "Technical Safeguards",
		Title: "Transmission Security - Encryption", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Implement a mechanism to encrypt electronic protected health information whenever deemed appropriate during transmission.",
	},
	{
		ID: "HIPAA-164.312(a)(1)", Framework: HIPAA, Category: "Technical Safeguards",
		Title: "Access Control", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Implement technical policies and procedures for electronic information systems that maintain electronic protected health information.",
	},
	{
		ID: "HIPAA-164.312(d)", Framework: HIPAA, Category: "Technical Safeguards",
		Title: "Person or Entity Authentication", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Implement procedures to verify that a person or entity seeking access to electronic protected health information is the one claimed.",
	},
	{
		ID: "HIPAA-164.312(b)", Framework: HIPAA, Category: "Technical Safeguards",
		Title: "Audit Controls", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI.",
	},
	{
		ID: "HIPAA-164.308(a)(6)", Framework: HIPAA, Category: "Administrative Safeguards",
		Title: "Security Incident Procedures", Severity: SeverityHigh, AutomationLevel: AutomationPartial,
		Description: "Implement policies and procedures to address security incidents, including response and reporting.",
	},
	{
		ID: "HIPAA-164.308(a)(7)", Framework: HIPAA, Category: "Administrative Safeguards",
		Title: "Contingency Plan", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Establish policies and procedures for responding to an emergency or other occurrence that damages systems that contain ePHI.",
	},
}

// NIST80053Controls defines NIST SP 800-53 Rev 5 controls relevant to KMS.
var NIST80053Controls = []Control{
	{
		ID: "NIST-SC-12", Framework: NIST80053, Category: "System and Communications Protection",
		Title: "Cryptographic Key Establishment and Management", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Establish and manage cryptographic keys when cryptography is employed within the system in accordance with applicable requirements.",
	},
	{
		ID: "NIST-SC-13", Framework: NIST80053, Category: "System and Communications Protection",
		Title: "Cryptographic Protection", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Implement FIPS-validated or NSA-approved cryptography in accordance with applicable laws and policies.",
	},
	{
		ID: "NIST-SC-8", Framework: NIST80053, Category: "System and Communications Protection",
		Title: "Transmission Confidentiality and Integrity", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Protect the confidentiality and integrity of transmitted information.",
	},
	{
		ID: "NIST-SC-28", Framework: NIST80053, Category: "System and Communications Protection",
		Title: "Protection of Information at Rest", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Protect the confidentiality and integrity of information at rest.",
	},
	{
		ID: "NIST-AC-2", Framework: NIST80053, Category: "Access Control",
		Title: "Account Management", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Define and manage system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
	},
	{
		ID: "NIST-AC-6", Framework: NIST80053, Category: "Access Control",
		Title: "Least Privilege", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Employ the principle of least privilege, allowing only authorized accesses for users necessary to accomplish assigned organizational tasks.",
	},
	{
		ID: "NIST-IA-2", Framework: NIST80053, Category: "Identification and Authentication",
		Title: "Identification and Authentication (Organizational Users)", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Uniquely identify and authenticate organizational users and associate that identification with processes acting on behalf of those users.",
	},
	{
		ID: "NIST-AU-2", Framework: NIST80053, Category: "Audit and Accountability",
		Title: "Event Logging", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Identify the types of events that the system is capable of logging in support of the audit function.",
	},
	{
		ID: "NIST-AU-3", Framework: NIST80053, Category: "Audit and Accountability",
		Title: "Content of Audit Records", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Ensure audit records contain sufficient information to establish what event occurred, when, where, and the outcome of the event.",
	},
	{
		ID: "NIST-CP-9", Framework: NIST80053, Category: "Contingency Planning",
		Title: "System Backup", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Conduct backups of user-level and system-level information at organization-defined frequency consistent with recovery time and recovery point objectives.",
	},
	{
		ID: "NIST-IR-4", Framework: NIST80053, Category: "Incident Response",
		Title: "Incident Handling", Severity: SeverityHigh, AutomationLevel: AutomationPartial,
		Description: "Implement an incident handling capability that includes preparation, detection, analysis, containment, eradication, and recovery.",
	},
}

// GDPRControls defines GDPR Article 32 and related controls applicable to KMS.
var GDPRControls = []Control{
	{
		ID: "GDPR-Art32-Encryption", Framework: GDPR, Category: "Technical Measures",
		Title: "Encryption of Personal Data", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Implement encryption of personal data as a technical measure to ensure a level of security appropriate to the risk (Article 32(1)(a)).",
	},
	{
		ID: "GDPR-Art32-Access", Framework: GDPR, Category: "Technical Measures",
		Title: "Confidentiality and Access Control", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Ensure the ongoing confidentiality, integrity, availability, and resilience of processing systems and services (Article 32(1)(b)).",
	},
	{
		ID: "GDPR-Art32-Resilience", Framework: GDPR, Category: "Technical Measures",
		Title: "Availability and Resilience", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Implement the ability to restore the availability and access to personal data in a timely manner in the event of an incident (Article 32(1)(c)).",
	},
	{
		ID: "GDPR-Art32-Testing", Framework: GDPR, Category: "Organisational Measures",
		Title: "Regular Testing and Assessment", Severity: SeverityHigh, AutomationLevel: AutomationPartial,
		Description: "Implement a process for regularly testing, assessing, and evaluating the effectiveness of technical and organisational measures (Article 32(1)(d)).",
	},
	{
		ID: "GDPR-Art30-Records", Framework: GDPR, Category: "Accountability",
		Title: "Records of Processing Activities", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Maintain records of processing activities including purposes, categories, recipients, transfers, time limits, and security measures (Article 30).",
	},
	{
		ID: "GDPR-Art33-Notification", Framework: GDPR, Category: "Breach Notification",
		Title: "Data Breach Notification", Severity: SeverityCritical, AutomationLevel: AutomationPartial,
		Description: "Notify the supervisory authority within 72 hours of becoming aware of a personal data breach (Article 33).",
	},
}

// CCPAControls defines CCPA/CPRA controls relevant to KMS.
var CCPAControls = []Control{
	{
		ID: "CCPA-1798.150-Encryption", Framework: CCPA, Category: "Data Security",
		Title: "Encryption of Personal Information", Severity: SeverityCritical, AutomationLevel: AutomationFull,
		Description: "Implement and maintain reasonable security procedures including encryption to protect consumers' personal information from unauthorized access.",
	},
	{
		ID: "CCPA-1798.100-Access", Framework: CCPA, Category: "Consumer Rights",
		Title: "Access Controls for Personal Information", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Implement access controls ensuring that personal information is only accessible to authorized personnel for disclosed business purposes.",
	},
	{
		ID: "CCPA-1798.150-Security", Framework: CCPA, Category: "Data Security",
		Title: "Reasonable Security Measures", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Implement and maintain reasonable security procedures and practices appropriate to the nature of the personal information.",
	},
	{
		ID: "CCPA-1798.105-Deletion", Framework: CCPA, Category: "Consumer Rights",
		Title: "Deletion and Crypto-Shredding Capability", Severity: SeverityHigh, AutomationLevel: AutomationFull,
		Description: "Implement the ability to delete or crypto-shred a consumer's personal information upon verified request through key rotation and destruction.",
	},
}

// ControlsForFramework returns all defined controls for the specified framework.
func ControlsForFramework(fw Framework) []Control {
	switch fw {
	case SOC2TypeII:
		return SOC2Controls
	case PCIDSS4:
		return PCIDSS4Controls
	case ISO27001:
		return ISO27001Controls
	case FedRAMPModerate:
		return FedRAMPControls
	case HIPAA:
		return HIPAAControls
	case NIST80053:
		return NIST80053Controls
	case GDPR:
		return GDPRControls
	case CCPA:
		return CCPAControls
	default:
		return nil
	}
}
