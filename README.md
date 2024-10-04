# serverless-ssh-ca

A Python wrapper around *ssh-keygen* to host a SSH Certificate Authority on AWS S3.

## Usage as developer

Generate a SSH key pair if don't have one already.
Please choose a strong passphrase to protect your key.

~~~ bash
ssh-keygen -t ed25519
~~~

Send the content of your public key (*~/.ssh/id_ed25519.pub*) to an admin and store the certificate that you got back next to your key.

Then configure your SSH client with the following shell script.
The two environment variables should be provided by your admin.

~~~ bash
echo "@cert-authority *.example.com ssh-ed25519 $(curl -sSf https://s3.$AWS_REGION.amazonaws.com/$SSHCA_BUCKET/public/sshca.pub)" >> ~/.ssh/known_hosts
cat << EOF >> ~/.ssh/config
Host *.example.com
  IdentityFile ~/.ssh/id_ed25519
  CertificateFile ~/.ssh/id_ed25519-cert.pub
  IdentitiesOnly yes
EOF
~~~

## Usage as admin

Install the *sshca* CLI on your workstation.

~~~ bash
pipx install git+https://github.com/dadevel/serverless-ssh-ca.git@main
~~~

Before you proceed login to your AWS account and set the usual environment variables (*AWS_ACCESS_KEY_ID*, *AWS_SECRET_ACCESS_KEY*, *AWS_REGION*).

If your SSH CA wasn't initialized yet, go to [CA Setup](#CA-Setup) first.

### Attestation

Sign a users SSH public key.
In this example the user *jdoe* has two roles.
What permissions actually come with a role is configured server-side (see [Authorization](#Authorization)).

~~~
❯ sshca sign -b mysshca -k ~/.ssh/id_ed25519.pub -u jdoe -r developer -r crash-reporter -v +30d
Enter passphrase: changeme
Signed user key /home/jdoe/.ssh/id_ed25519-cert.pub: id "jdoe" serial 1 for developer,crash-reporter
ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAx...zFbIKlb0rvbfIbB0C93yEoebrpHa1wA=
~~~

> **Explanation**
>
> *-b*  name of the S3 bucket  
> *-k*  path to or content of the SSH public key to sign  
> *-u*  username, embedded in certificate with *user:* prefix, also logged by servers during sign-in  
> *-r*  alphanumeric string embedded in certificate with *role:* prefix, option can be specified multiple times  

Sign the SSH public key of a server.

~~~
❯ sshca sign -b mysshca -k 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEtLn+O7...' -f srv01.dev.example.com -v +365d
Enter passphrase: changeme
Signed host key /tmp/sshca-m15n938c/id-cert.pub: id "srv01.dev.example.com" serial 2 for srv01.dev.example.com
ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAx.../ffzaaWipX+kUIYFJDMqAXuiLdXZRccA4=
~~~

### Revocation

Get the certificate log, note the serial number of the compromised certificate and revoke the serial number.

~~~ bash
sshca get-log -b mysshca | less
sshca revoke -b mysshca -s 1
~~~

### Authorization

The following example allows the user *jdoe* to login as himself and users with the role *administrator* to login as *root*.
Note that all other server options, e.g. *AllowUsers* or *AllowGroups*, still take effect.

~~~ bash
echo user:jdoe >> /home/jdoe/.ssh/authorized_principals
echo role:administrator >> /root/.ssh/authorized_principals
~~~

## CA Setup

### AWS Preparation

Create an IAM group and a S3 bucket.
Then assign a bucket policy that gives the group read/write access on the bucket and allows anonymous read on the *public/* prefix.

~~~ bash
SSHCA_GROUP=sshca-admins SSHCA_BUCKET=mysshca
aws iam create-group --group-name $SSHCA_GROUP
aws s3api create-bucket --create-bucket-configuration LocationConstraint=$AWS_REGION --bucket $SSHCA_BUCKET --object-ownership BucketOwnerEnforced
aws s3api delete-public-access-block --bucket $SSHCA_BUCKET
cat << EOF > ./policy.json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$SSHCA_BUCKET/public/*"
    },
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):group/$SSHCA_GROUP"
      },
      "Action": [
        "s3:DeleteObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::$SSHCA_BUCKET",
        "arn:aws:s3:::$SSHCA_BUCKET/*"
     ]
    }
  ]
}
EOF
aws s3api put-bucket-policy --bucket $SSHCA_BUCKET --policy file://policy.json
~~~

### Initialization

Now initialize your new SSH CA.
This will generate a private key, encrypt it with a passphrase and upload the encrypted key together with some additional files to the S3 bucket.
Please choose a strong passphrase to sufficiently protect the key.

~~~
❯ export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=.. AWS_REGION=...
❯ sshca init -b mysshca
Enter passphrase (empty for no passphrase): changeme
❯ aws s3 ls --recursive s3://mysshca
2024-10-05 02:02:23        480 private/sshca.key
2024-10-05 02:02:23          0 private/sshca.log
2024-10-05 02:02:23         44 public/sshca.krl
2024-10-05 02:02:23         82 public/sshca.pub
~~~

## Server Setup

Sign the host public key (see [Attestation](#Attestation)) and transfer the resulting certificate to the server.

~~~ bash
echo ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAx.../ffzaaWipX+kUIYFJDMqAXuiLdXZRA4= > /etc/ssh/ssh_host_ed25519_key-cert.pub
~~~

Configure OpenSSH to trust certificates from your CA.

~~~ bash
cat << EOF > /etc/ssh/sshd_config.d/50-sshca.conf
TrustedUserCAKeys /etc/ssh/sshca.pub
CASignatureAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com
RevokedKeys /etc/ssh/sshca.krl
HostKey /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
AuthorizedPrincipalsFile %h/.ssh/authorized_principals
EOF
~~~

Configure a Systemd timer for periodic updates of the key revocation list.
The shorter the interval, the faster revoked certificates are actually rejected.

~~~ bash
cat << EOF > /etc/systemd/system/sshca-krl-update.timer
[Unit]
Description=SSHCA KRL Updater

[Timer]
OnCalendar=hourly
AccuracySec=5min
RandomizedDelaySec=30min
FixedRandomDelay=true

[Install]
WantedBy=timers.target
EOF
cat << EOF > /etc/systemd/system/sshca-krl-update.service
[Unit]
Description=SSHCA KRL Updater
Requires=network-online.target nss-lookup.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
ExecStart=curl -sSf https://s3.$AWS_REGION.amazonaws.com/$SSHCA_BUCKET/public/sshca.krl -o /etc/ssh/sshca.krl
EOF
systemctl enable --now sshca-krl-update.timer
~~~

Optional: Configure an additional Systemd timer that terminates long-running SSH sessions to force reauthentication.
Otherwise open sessions might remain after a certificate was revoked.

~~~ bash
cat << EOF > /etc/systemd/system/sshd-session-limit.timer
[Unit]
Description=OpenSSH Session Duration Limiter

[Timer]
OnCalendar=hourly
AccuracySec=5min

[Install]
WantedBy=timers.target
EOF
cat << EOF > /etc/systemd/system/sshd-session-limit.service
[Unit]
Description=OpenSSH Session Duration Limiter
After=basic.target

[Service]
Type=oneshot
# terminate sessions after 12h
ExecStart=pkill --uid 0 --older 43200 --exact sshd-session
EOF
systemctl enable --now sshd-session-limit.timer
~~~
