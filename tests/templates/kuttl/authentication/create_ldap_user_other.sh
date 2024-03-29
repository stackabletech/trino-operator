#!/bin/sh

# To check the existing users
# ldapsearch -H ldap://localhost:1389 -D cn=admin,dc=example,dc=org -w admin -b ou=users,dc=example,dc=org

# To check the new user
# ldapsearch -H ldap://localhost:1389 -D cn=integrationtest,ou=users,dc=example,dc=org -w integrationtest -b ou=users,dc=example,dc=org

cat << 'EOF' | ldapadd -H ldap://localhost:1389 -D cn=admin,dc=example,dc=org -w admin
dn: cn=integrationtest-other,ou=users,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: integrationtest-other
uid: integrationtest-other
givenName: Stackable
sn: Integration-Test
mail: integrationtest-other@stackable.de
uidNumber: 16842
gidNumber: 100
homeDirectory: /home/integrationtest-other
loginShell: /bin/bash
userPassword: {crypt}x
shadowLastChange: 0
shadowMax: 0
shadowWarning: 0
EOF

ldappasswd -H ldap://localhost:1389 -D cn=admin,dc=example,dc=org -w admin -s integrationtest-other "cn=integrationtest-other,ou=users,dc=example,dc=org"
