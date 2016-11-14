#!  /bin/sh

OPENSSL=`which openssl`

PRIVATE_PEM=../src/androidTest/assets/private.pem
ENCRYPTED_PRIVATE_PEM=../src/androidTest/assets/encrypted_private.pem
PKCS8_ENCRYPTED_PRIVATE_PEM=../src/androidTest/assets/pkcs8_encrypted_private.pem
PUBLIC_PEM=../src/androidTest/assets/public.pem
PASSWORD_TXT=../src/androidTest/assets/password.txt

while getopts "p:" opt; do
	case "$opt" in
		p)
			OPENSSL=$OPTARG
			;;
	esac
done

${OPENSSL} genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ${PRIVATE_PEM}
${OPENSSL} rsa -in ${PRIVATE_PEM} -aes256 -passout file:${PASSWORD_TXT} -out ${ENCRYPTED_PRIVATE_PEM}
${OPENSSL} rsa -in ${PRIVATE_PEM} -pubout -out ${PUBLIC_PEM}
${OPENSSL} pkcs8 -in ${PRIVATE_PEM} -topk8 -v2 aes-256-cbc -passout file:${PASSWORD_TXT}  -out ${PKCS8_ENCRYPTED_PRIVATE_PEM}
