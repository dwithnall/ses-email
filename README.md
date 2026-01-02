# SES Email Domain Provisioning Tool

This tool automates the complete setup of Amazon SES (Simple Email Service) for a domain, including domain verification, DKIM configuration, DNS record creation in CloudFlare, and IAM user provisioning for secure email sending.

This was mostly developed by an AI beause I'm lazy. Use at your own risk.

I developed this because I wanted an easy way to deploy WordPress sites using SES as a transactional email service. The outputs provide a copy/pasta sample for updated the WordPress config for [FluentSMTP](https://fluentsmtp.com/).

## What This Tool Does

The `provision_ses_domain.py` script performs the following automated tasks:

1. **SES Domain Verification**: Verifies your domain with Amazon SES
2. **DKIM Configuration**: Sets up DomainKeys Identified Mail for email authentication
3. **DNS Record Creation**: Automatically creates all required DNS records in CloudFlare:
   - SES verification TXT record
   - DKIM CNAME records
   - MX record for MAIL FROM domain (optional for outgoing-only email)
   - SPF record for email authentication
   - DMARC record for email policy
4. **IAM User Creation**: Creates a dedicated IAM user with minimal permissions for sending emails
5. **SMTP Credentials**: Generates secure SMTP credentials for your applications
6. **Feedback Email Configuration**: Optionally configures SES feedback forwarding for bounces and complaints
7. **Comprehensive Logging**: Creates detailed logs of all operations

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
                "iam:GetPolicy",
                "iam:DetachUserPolicy",
                "iam:ListAccessKeys",
                "iam:DeleteAccessKey",
                "iam:DeleteUser",
                "iam:ListPolicyVersions",
                "iam:DeletePolicyVersion",
                "iam:DeletePolicy"
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

**Note:** The IAM permissions include both creation and deletion operations. If you only need to provision domains (not remove them), you can remove the deletion-related permissions:
- `iam:DetachUserPolicy`
- `iam:ListAccessKeys`
- `iam:DeleteAccessKey`
- `iam:DeleteUser`
- `iam:ListPolicyVersions`
- `iam:DeletePolicyVersion`
- `iam:DeletePolicy`

However, if you want to use the `--remove-aws-resources` flag, all permissions listed above are required.


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

**Note**: If you use the `--no-cloudflare` flag, you can omit the `[Cloudflare]` section from your config file.

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

# Skip CloudFlare integration (manual DNS setup required)
python provision_ses_domain.py yourdomain.com --no-cloudflare

# Enable SES feedback email forwarding for bounces and complaints
python provision_ses_domain.py yourdomain.com --enable-feedback

# Remove all SES-related DNS records from CloudFlare
python provision_ses_domain.py yourdomain.com --remove-cloudflare-records

# Remove IAM user and policy for this domain
python provision_ses_domain.py yourdomain.com --remove-aws-resources
```

### Using Without CloudFlare

If you don't use CloudFlare for DNS management, you can use the `--no-cloudflare` flag to skip CloudFlare integration:

```bash
python provision_ses_domain.py yourdomain.com --no-cloudflare
```

When using this option:
- The script will still configure SES and create the IAM user
- You'll need to manually create the DNS records in your DNS provider
- The script will output the exact DNS records you need to create
- No CloudFlare API token is required in your config file

### SES Feedback Email

By default, SES feedback email forwarding is **disabled**. This means you won't receive notifications for bounces and complaints.

To enable feedback email forwarding, use the `--enable-feedback` flag:

```bash
python provision_ses_domain.py yourdomain.com --enable-feedback
```

**What feedback emails include:**
- **Bounce notifications**: When emails cannot be delivered
- **Complaint notifications**: When recipients mark emails as spam
- **Delivery notifications**: When emails are successfully delivered

**Important considerations:**
- Feedback emails are sent to the address specified in the `Return-Path` header of your emails
- Ensure you monitor the feedback email address to handle bounces and complaints
- High bounce and complaint rates can affect your sending reputation
- You can combine this with other flags: `--enable-feedback --no-cloudflare`

### Removing CloudFlare DNS Records

To remove all SES-related DNS records from CloudFlare for a domain, use the `--remove-cloudflare-records` flag:

```bash
python provision_ses_domain.py yourdomain.com --remove-cloudflare-records
```

**What gets removed:**
- SES domain verification TXT record (`_amazonses.{domain}`)
- All DKIM CNAME records (`{token}._domainkey.{domain}`)
- MAIL FROM MX record
- MAIL FROM SPF TXT record
- DMARC TXT record (`_dmarc.{domain}`)

**Important notes:**
- This operation only removes DNS records from CloudFlare
- It does NOT remove the SES identity or IAM user from AWS
- You must have CloudFlare configured (cannot use with `--no-cloudflare`)
- This is useful when reprovisioning a domain or cleaning up after decommissioning

### Removing AWS IAM Resources

To remove the IAM user and policy created for a domain, use the `--remove-aws-resources` flag:

```bash
python provision_ses_domain.py yourdomain.com --remove-aws-resources
```

**What gets removed:**
- IAM user (`ses-sender-{domain}`)
- All access keys associated with the user
- IAM policy (`ses-send-only-{domain}`)
- Policy attachments from the user

**Important notes:**
- **Required Permissions**: Your AWS user must have the following IAM permissions to use this feature:
  - `iam:DetachUserPolicy`
  - `iam:ListAccessKeys`
  - `iam:DeleteAccessKey`
  - `iam:DeleteUser`
  - `iam:ListPolicyVersions`
  - `iam:DeletePolicyVersion`
  - `iam:DeletePolicy`
- This operation only removes IAM resources (user and policy)
- It does NOT remove the SES identity or DNS records
- The policy will only be deleted if it's not attached to other entities
- Access keys are deleted before the user is removed
- This is useful when decommissioning a domain or cleaning up resources

**Note:** You can combine cleanup flags:
```bash
# Remove both CloudFlare DNS records and AWS IAM resources
python provision_ses_domain.py yourdomain.com --remove-cloudflare-records --remove-aws-resources
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

## DNS Records Created

The script creates the following DNS records in CloudFlare:

1. **SES Verification (TXT)** - Required
   - Name: `_amazonses.{domain}`
   - Purpose: Verifies domain ownership with AWS SES

2. **DKIM Signing (CNAME)** - Required (3 records)
   - Name: `{token}._domainkey.{domain}`
   - Purpose: Enables DKIM email authentication

3. **MAIL FROM (MX)** - Optional
   - Name: `{mail-from-subdomain}.{domain}` (default: `mail.{domain}`)
   - Purpose: Handles bounce/complaint notifications
   - **Can be skipped with `--skip-mx` for outgoing-only transactional email**

4. **SPF (TXT)** - Required
   - Name: `{mail-from-subdomain}.{domain}`
   - Purpose: Authorizes AWS SES to send email on your behalf

5. **DMARC (TXT)** - Recommended
   - Name: `_dmarc.{domain}`
   - Purpose: Email authentication policy (defaults to 'none' policy)

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

#### Permissions Granted to the New IAM User

The script creates an IAM policy with the following permissions for the new user:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ses:SendRawEmail",
                "ses:SendEmail"
            ],
            "Resource": "arn:aws:ses:{region}:{account-id}:identity/{domain}"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ses:ListIdentities",
                "ses:GetIdentityVerificationAttributes",
                "ses:GetIdentityDkimAttributes",
                "ses:SetIdentityFeedbackForwardingEnabled"
            ],
            "Resource": "*"
        }
    ]
}
```

**What these permissions allow:**
- `ses:SendEmail` and `ses:SendRawEmail`: Send emails through SES for the specific domain
- `ses:ListIdentities`: List SES identities (needed for some email libraries)
- `ses:GetIdentityVerificationAttributes`: Check verification status of identities
- `ses:GetIdentityDkimAttributes`: Retrieve DKIM configuration details
- `ses:SetIdentityFeedbackForwardingEnabled`: Configure feedback email forwarding for bounces and complaints

**Security features:**
- Permissions are scoped to the specific domain only
- No administrative access to SES or other AWS services
- Cannot modify SES configuration or create new identities
- Cannot access other AWS resources outside of SES

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

5. **MX record not needed**
   - For outgoing-only transactional email, use `--skip-mx` to skip MX record creation
   - The MX record is only needed for receiving bounce/complaint notifications at the MAIL FROM subdomain

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

## Contributing

Contributions are welcome! However, please note that I have limited time available, so I may not be able to respond to issues or pull requests promptly.

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** and test thoroughly
4. **Commit your changes**: `git commit -m 'Add some amazing feature'`
5. **Push to the branch**: `git push origin feature/amazing-feature`
6. **Open a Pull Request**

### Guidelines

- Please test your changes before submitting
- Update documentation if needed
- Keep changes focused and well-documented
- Follow existing code style and patterns

### Issues

While I appreciate bug reports and feature requests, I may not have time to respond to all issues. Feel free to:
- Fork the project and fix issues yourself
- Submit pull requests with fixes
- Discuss solutions in the issues

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

The MIT License is one of the most permissive open source licenses, allowing you to:
- Use the code for any purpose (commercial or non-commercial)
- Modify the code as you see fit
- Distribute the code
- Use it privately
- Sublicense it

The only requirement is that you include the original copyright notice and license text when redistributing. 