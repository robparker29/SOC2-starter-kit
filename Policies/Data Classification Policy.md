# Data Classification Policy

**Document Version:** 1.0  
**Effective Date:** [DATE]  
**Review Date:** [DATE + 1 YEAR]  
**Owner:** [DATA PROTECTION OFFICER / CISO / CTO]  
**Approved By:** [CEO], [CTO/CISO]  

---

## 1. Purpose & Scope

This policy establishes a framework for classifying information assets based on their sensitivity, value, and criticality to [COMPANY NAME]. It defines handling requirements for each classification level to ensure appropriate protection throughout the data lifecycle.

**Why this matters:** SOC 2 auditors need to see that you understand what data you have and how it should be protected. Data classification is the foundation for implementing appropriate security controls based on data sensitivity.

### 1.1 Scope
This policy applies to:
- All information created, processed, stored, or transmitted by the organization
- Data in all formats including electronic, paper, and verbal communications
- Information owned by the company and data entrusted to the company by customers or partners
- All employees, contractors, and third parties handling company information
- All systems, applications, and storage locations containing organizational data

### 1.2 Objectives
- Establish consistent data classification criteria across the organization
- Define appropriate security controls for each data classification level
- Enable risk-based protection of information assets
- Support compliance with legal, regulatory, and contractual requirements
- Facilitate proper data handling and sharing decisions

---

## 2. Data Classification Framework

### 2.1 Classification Levels

**PUBLIC**
- Information intended for public disclosure or already publicly available
- No adverse impact if disclosed, modified, or destroyed
- Marketing materials, published documentation, public website content

**INTERNAL**
- Information intended for use within the organization
- Limited adverse impact if disclosed outside the organization
- Internal procedures, employee directories, general business communications

**CONFIDENTIAL**
- Sensitive information requiring protection from unauthorized disclosure
- Moderate to significant adverse impact if compromised
- Customer data, financial information, business plans, personnel records

**RESTRICTED**
- Highly sensitive information requiring the highest level of protection
- Severe adverse impact if compromised
- Trade secrets, intellectual property, regulated data, authentication credentials

### 2.2 Classification Criteria

**Sensitivity Assessment:**
- Legal and regulatory requirements for protection
- Competitive advantage and intellectual property value
- Privacy implications and personal data elements
- Contractual obligations and customer requirements

**Impact Assessment:**
- Financial impact of unauthorized disclosure or loss
- Regulatory penalties and legal consequences
- Reputation and brand damage potential
- Operational disruption and business continuity impact

---

## 3. Data Classification Process

### 3.1 Classification Responsibility

**Data Owners**
- Business executives or managers responsible for business processes that create or use data
- Determine appropriate classification level based on business value and sensitivity
- Approve access rights and sharing arrangements
- Review and update classifications based on changing business needs

**Data Custodians**
- IT staff responsible for technical implementation of data protection controls
- Implement security controls appropriate to classification level
- Monitor compliance with handling requirements
- Report classification-related security incidents

**Data Users**
- All individuals who access, process, or handle classified information
- Follow handling requirements appropriate to data classification
- Report suspected misclassification or security concerns
- Maintain confidentiality and protection obligations

### 3.2 Classification Assignment
- All new data must be classified at the time of creation or acquisition
- Classification based on the most sensitive information contained within the dataset
- When in doubt, assign higher classification level pending formal review
- Regular review and reclassification based on changing business or regulatory requirements

---

## 4. Handling Requirements by Classification

### 4.1 PUBLIC Data Handling
**Access Controls:**
- No access restrictions required
- Available to general public through approved channels

**Storage & Transmission:**
- Standard backup and recovery procedures
- No encryption required for transmission
- Public distribution channels acceptable

**Retention & Disposal:**
- Standard retention schedules apply
- No special disposal requirements

### 4.2 INTERNAL Data Handling
**Access Controls:**
- Access limited to employees and authorized contractors
- Standard authentication required
- Role-based access permissions

**Storage & Transmission:**
- Stored on company-approved systems and locations
- Encrypted transmission over external networks
- Cloud storage in approved business applications

**Retention & Disposal:**
- Business-driven retention schedules
- Secure deletion when no longer needed
- Standard disposal procedures for physical media

### 4.3 CONFIDENTIAL Data Handling
**Access Controls:**
- Access limited to individuals with legitimate business need
- Multi-factor authentication required for system access
- Access logging and monitoring implemented
- Non-disclosure agreements required for external parties

**Storage & Transmission:**
- Encrypted storage on approved systems
- Encrypted transmission for all communications
- Approved cloud services with appropriate security controls
- Physical documents secured in locked storage

**Retention & Disposal:**
- Formal retention schedules with regular review
- Secure deletion or destruction when retention period expires
- Certificate of destruction for physical media
- Data purging verification for electronic systems

### 4.4 RESTRICTED Data Handling
**Access Controls:**
- Access limited to specifically authorized individuals
- Enhanced authentication and authorization controls
- Privileged access management and monitoring
- Formal approval process for access grants
- Confidentiality agreements and background checks required

**Storage & Transmission:**
- Encrypted storage with enhanced key management
- End-to-end encryption for all transmissions
- Segregated storage systems with additional security controls
- Physical documents in secured facilities with access logs

**Retention & Disposal:**
- Formal retention policy with legal and compliance review
- Secure destruction with verified evidence of disposal
- Witness certification for destruction of physical documents
- Cryptographic erasure and multi-pass deletion for electronic systems

**Industry Customization Notes:**
- **Financial Services:** Add specific requirements for PCI data, financial records, and trading information
- **Healthcare:** Include PHI classification and HIPAA-specific handling requirements
- **SaaS/Technology:** Focus on customer data classification and multi-tenant data isolation
- **International:** Add GDPR personal data categories and cross-border transfer restrictions

---

## 5. Data Labeling & Marking

### 5.1 Electronic Data Labeling
- Metadata classification tags in document properties
- Classification headers or footers in documents and emails
- System-level classification labels for databases and applications
- Automated classification tools where feasible

### 5.2 Physical Document Marking
- Classification level prominently displayed on each page
- Cover sheets for confidential and restricted documents
- Colored paper or folders for different classification levels
- Secure containers for storage and transport

### 5.3 Classification Changes
- Clear procedures for upgrading or downgrading classification
- Documentation of classification change rationale
- Notification to all affected parties and systems
- Update of all labels, markings, and system metadata

---

## 6. Data Sharing & Disclosure

### 6.1 Internal Sharing
- Share only with individuals having legitimate business need
- Maintain classification level throughout internal distribution
- Document sharing decisions and approvals
- Regular review of ongoing access and sharing arrangements

### 6.2 External Sharing
**Third-Party Sharing Requirements:**
- Formal agreements including confidentiality and security requirements
- Recipient capability assessment for handling classified information
- Limited sharing scope and duration aligned with business purpose
- Regular monitoring and audit of third-party data handling

**Customer Data Sharing:**
- Customer consent or contractual authorization required
- Compliance with privacy laws and regulations
- Data minimization and purpose limitation principles
- Secure transmission and handling by recipients

### 6.3 Public Disclosure
- Formal approval process for releasing confidential or restricted information
- Legal review for potential regulatory or contractual implications
- Coordination with public relations and communications teams
- Documentation of disclosure decisions and approvals

---

## 7. Compliance & Monitoring

### 7.1 Classification Compliance
- Regular audits of data classification implementation
- Verification of appropriate security controls for each classification level
- Assessment of user compliance with handling requirements
- Remediation of identified classification gaps or violations

### 7.2 Data Discovery & Inventory
- Automated tools for discovering and classifying unstructured data
- Regular inventory of data stores and classification status
- Assessment of shadow IT and unmanaged data repositories
- Integration with data loss prevention and monitoring systems

### 7.3 Metrics & Reporting
- Classification coverage metrics by data type and system
- User training completion and awareness levels
- Security incident analysis by data classification level
- Compliance assessment results and remediation status

---

## 8. Training & Awareness

### 8.1 Classification Training Requirements
**All Personnel:**
- Data classification awareness training within 30 days of hire
- Annual refresher training on classification requirements
- Role-specific training for data owners and custodians

**Training Content:**
- Classification level definitions and criteria
- Handling requirements for each classification level
- Proper labeling and marking procedures
- Incident reporting and escalation procedures

### 8.2 Ongoing Awareness
- Regular communications about data classification best practices
- Examples and case studies of proper and improper data handling
- Updates on classification policy changes and new requirements

---

## 9. Implementation Guidance

### 9.1 Getting Started Checklist
- [ ] Identify data owners for major business processes and systems
- [ ] Conduct initial data inventory and classification assessment
- [ ] Develop classification guidelines for common data types
- [ ] Implement basic labeling and marking procedures
- [ ] Train key personnel on classification requirements
- [ ] Establish classification review and update processes
- [ ] Integrate classification with existing security controls

### 9.2 Quick Start for Small Organizations
Essential data classification activities to implement first:
1. Classify major data categories (customer data, financial data, intellectual property)
2. Implement basic handling requirements for confidential data
3. Train all staff on classification levels and handling rules
4. Establish secure storage and transmission procedures
5. Create simple data sharing approval process

### 9.3 Scaling Considerations
As your organization grows:
- **10-50 employees:** Basic classification levels, manual processes, simple controls
- **50-200 employees:** Formal data owner roles, automated labeling tools, enhanced monitoring
- **200+ employees:** Advanced classification schemes, automated discovery tools, comprehensive compliance programs

---

## 10. Related Documents
- Information Security Policy
- Access Control Policy
- Data Retention & Disposal Policy
- Privacy Policy
- Vendor Risk Management Policy
- Incident Response Plan

---

## 11. Document Control

| Version | Date | Changes | Approved By |
|---------|------|---------|-------------|
| 1.0 | [DATE] | Initial policy creation | [CEO], [CTO] |

---

*This policy is reviewed annually and updated as needed to reflect changes in business requirements, data types, and regulatory environment.*
