# SES Email Domain Provisioning Tool

This tool automates the complete setup of Amazon SES (Simple Email Service) for a domain, including domain verification, DKIM configuration, DNS record creation in CloudFlare, and IAM user provisioning for secure email sending.

This was mostly developed by an AI beause I'm lazy. Use are your own risk.

## What This Tool Does

The `provision_ses_domain.py` script performs the following automated tasks:

1. **SES Domain Verification**: Verifies your domain with Amazon SES
2. **DKIM Configuration**: Sets up DomainKeys Identified Mail for email authentication
3. **DNS Record Creation**: Automatically creates all required DNS records in CloudFlare:
   - SES verification TXT record
   - DKIM CNAME records
   - MX record for MAIL FROM domain
   - SPF record for email authentication
   - DMARC record for email policy
4. **IAM User Creation**: Creates a dedicated IAM user with minimal permissions for sending emails
5. **SMTP Credentials**: Generates secure SMTP credentials for your applications
6. **Comprehensive Logging**: Creates detailed logs of all operations

## Prerequisites

Before running this tool, you need:

- A domain registered and managed through CloudFlare
- An AWS account with appropriate permissions
- Python 3.6+ installed
- Required Python packages (see Installation section)

## Installation

1. **Clone or download this repository**
2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Setup Instructions

### Step 1: Create AWS IAM User with Required Permissions

You need an AWS user with permissions to manage SES, IAM, and STS.
This policy is for the user/role executing the script, not the one being created. It needs broad permissions.

#### Using AWS Console Create/Update the IAM Policy for the Script Runner

Go to the IAM console in AWS -> Policies -> Create Policy.
Use the JSON editor and paste the following policy.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SESManagement",
            "Effect": "Allow",
            "Action": [
                "ses:VerifyDomainIdentity",
                "ses:VerifyDomainDkim",
                "ses:SetIdentityMailFromDomain",
                "ses:GetIdentityVerificationAttributes"
            ],
            "Resource": "*"
        },
        {
            "Sid": "IAMUserAndPolicyManagementForSES",
            "Effect": "Allow",
            "Action": [
                "iam:CreateUser",
                "iam:CreatePolicy",
                "iam:AttachUserPolicy",
                "iam:CreateAccessKey",
                "iam:GetUser",
                "iam:GetPolicy"
            ],
            "Resource": "*"
        },
        {
            "Sid": "STSPermissions",
            "Effect": "Allow",
            "Action": "sts:GetCallerIdentity",
            "Resource": "*"
        }
    ]
}
```

Attach this policy to the IAM user or role that you will use to run the script.
Generate and configure the Access Key and Secret for this script-running user.


### Step 2: Create CloudFlare API Token

1. **Log into CloudFlare Dashboard**
2. **Navigate to API Tokens**: My Profile → API Tokens
3. **Create Custom Token** with the following permissions:
   - **Zone Permissions**: Zone → Zone:Read, DNS:Edit
   - **Zone Resources**: Include → All zones
   - **Account Resources**: Include → All accounts
   - **Account Permissions**: Account → Account:Read

![Cloudflare Token Permissions](/assets/images/cloudflare-token.png "Cloudflare Token")

1. **Set token name**: `ses-provisioning-token` (or your preferred name)
2. **Create token** and **save the token value**

### Step 3: Create Configuration File

Create a `config.ini` file in the same directory as the script (There is a sample available `config.bak`):

```ini
[AWS]
access_key_id = YOUR_AWS_ACCESS_KEY_ID
secret_access_key = YOUR_AWS_SECRET_ACCESS_KEY
region = us-east-1

[Cloudflare]
api_token = YOUR_CLOUDFLARE_API_TOKEN
```

**Important**: Replace the placeholder values with your actual credentials.

## Usage

### Basic Usage

```bash
python provision_ses_domain.py yourdomain.com
```

### Advanced Usage

```bash
# Use custom configuration file
python provision_ses_domain.py yourdomain.com --config my-config.ini

# Use custom MAIL FROM subdomain
python provision_ses_domain.py yourdomain.com --mail-from-subdomain email
```

### Example

```bash
python provision_ses_domain.py example.com
```

This will:
- Verify `example.com` with SES
- Create MAIL FROM domain `mail.example.com`
- Set up all DNS records in CloudFlare
- Create IAM user `ses-sender-example-com`
- Generate SMTP credentials

## Output

The script will:

1. **Create a detailed log file** with timestamp: `ses-provision-{domain}-{timestamp}.log`
2. **Display credentials** for your applications:
   - AWS Access Keys for programmatic access
   - SMTP credentials for email sending
   - WordPress FluentMail configuration

### Sample Output

```
--- ✅ Provisioning Complete! ✅ ---

AWS ACCESS KEYS (for programmatic access):
  AWS_ACCESS_KEY_ID:     AKIAIOSFODNN7EXAMPLE
  AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY
  AWS_REGION:            us-east-1

SES SMTP CREDENTIALS (for email sending):
  SES SMTP Endpoint:     smtp.mail.us-east-1.amazonaws.com
  SMTP Username:         AKIAIOSFODNN7EXAMPLE
  SMTP Password:         wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY

Fluentmail credentials (paste into WordPress Config):
define('FLUENTMAIL_AWS_ACCESS_KEY_ID', 'AKIAIOSFODNN7EXAMPLE');
define('FLUENTMAIL_AWS_SECRET_ACCESS_KEY', 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY');


```

## What Happens After Provisioning

### DNS Propagation
- DNS records typically propagate within 5-30 minutes
- You can check propagation using tools like `dig` or online DNS checkers

### AWS Verification
- AWS will automatically detect the DNS records
- Check the SES Console → Identities to see verification status
- Domain should show as "Verified" once DNS propagates

### Email Sending
- Your domain will be in "Sandbox Mode" initially
- To send to any email address, request production access in SES Console
- In sandbox mode, you can only send to verified email addresses

## Security Considerations

### IAM Permissions
The tool creates a dedicated IAM user with minimal permissions:
- Can only send emails via SES for the specific domain
- Cannot access other AWS services
- Cannot modify SES configuration

### CloudFlare API Token
- The API token has minimal required permissions
- Only can read zones and edit DNS records
- Cannot access other CloudFlare features

### Credential Storage
- Store credentials securely
- Never commit `config.ini` to version control
- Consider using AWS Secrets Manager for production

## Troubleshooting

### Common Issues

1. **"Domain not found in CloudFlare"**
   - Ensure the domain is added to your CloudFlare account
   - Verify the domain name is spelled correctly

2. **"Access Denied" errors**
   - Check that your AWS user has the required permissions
   - Verify your CloudFlare API token has DNS edit permissions

3. **DNS records not appearing**
   - Check CloudFlare API token permissions
   - Verify the domain is active in CloudFlare

4. **SES verification fails**
   - Wait for DNS propagation (5-30 minutes)
   - Check that all DNS records were created correctly

### Log Files
- Check the generated log file for detailed error information
- Log files are named: `ses-provision-{domain}-{timestamp}.log`

## Files Created

- **Log file**: `ses-provision-{domain}-{timestamp}.log`
- **IAM User**: `ses-sender-{domain}`
- **IAM Policy**: `ses-send-only-{domain}`
- **DNS Records**: Various records in CloudFlare

## Support

For issues or questions:
1. Check the log file for detailed error messages
2. Verify all prerequisites are met
3. Ensure credentials have correct permissions

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

The MIT License is one of the most permissive open source licenses, allowing you to:
- Use the code for any purpose (commercial or non-commercial)
- Modify the code as you see fit
- Distribute the code
- Use it privately
- Sublicense it

The only requirement is that you include the original copyright notice and license text when redistributing. 