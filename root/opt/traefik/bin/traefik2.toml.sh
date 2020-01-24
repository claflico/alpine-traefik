#!/usr/bin/env sh

TRAEFIK_HTTP_PORT=${TRAEFIK_HTTP_PORT:-"8080"}
TRAEFIK_HTTPS_ENABLE=${TRAEFIK_HTTPS_ENABLE:-"false"}
TRAEFIK_HTTPS_PORT=${TRAEFIK_HTTPS_PORT:-"8443"}
TRAEFIK_HTTPS_MIN_TLS=${TRAEFIK_HTTPS_MIN_TLS:-"VersionTLS12"}
TRAEFIK_HTTPS_OPTS=${TRAEFIK_HTTPS_OPTS:-""}
TRAEFIK_ADMIN_ENABLE=${TRAEFIK_ADMIN_ENABLE:-"false"}
TRAEFIK_ADMIN_PORT=${TRAEFIK_ADMIN_PORT:-"8000"}
TRAEFIK_DEBUG=${TRAEFIK_DEBUG:="false"}
TRAEFIK_INSECURE_SKIP=${TRAEFIK_INSECURE_SKIP:="false"}
TRAEFIK_LOG_LEVEL=${TRAEFIK_LOG_LEVEL:-"INFO"}
TRAEFIK_LOG_FILE=${TRAEFIK_LOG_FILE:-${SERVICE_HOME}"/log/traefik.log"}
TRAEFIK_ACCESS_FILE=${TRAEFIK_ACCESS_FILE:-${SERVICE_HOME}"/log/access.log"}
TRAEFIK_SSL_PATH=${TRAEFIK_SSL_PATH:-${SERVICE_HOME}"/certs"}
TRAEFIK_SSL_KEY_FILE=${TRAEFIK_SSL_KEY_FILE:-${TRAEFIK_SSL_PATH}"/"${SERVICE_NAME}".key"}
TRAEFIK_SSL_CRT_FILE=${TRAEFIK_SSL_CRT_FILE:-${TRAEFIK_SSL_PATH}"/"${SERVICE_NAME}".crt"}
TRAEFIK_SSL_OPTS=${TRAEFIK_SSL_OPTS:-""}
TRAEFIK_TIMEOUT_READ=${TRAEFIK_TIMEOUT_READ:-"0"}
TRAEFIK_TIMEOUT_WRITE=${TRAEFIK_TIMEOUT_WRITE:-"0"}
TRAEFIK_TIMEOUT_IDLE=${TRAEFIK_TIMEOUT_IDLE:-"180"}
TRAEFIK_TIMEOUT_DIAL=${TRAEFIK_TIMEOUT_DIAL:-"30"}
TRAEFIK_TIMEOUT_HEADER=${TRAEFIK_TIMEOUT_HEADER:-"0"}
TRAEFIK_TIMEOUT_GRACE=${TRAEFIK_TIMEOUT_GRACE:-"10"}
TRAEFIK_TIMEOUT_ACCEPT=${TRAEFIK_TIMEOUT_ACCEPT:-"0"}
TRAEFIK_RANCHER_ENABLE=${TRAEFIK_RANCHER_ENABLE:-"false"}
TRAEFIK_RANCHER_REFRESH=${TRAEFIK_RANCHER_REFRESH:-15}
TRAEFIK_RANCHER_EXPOSED=${TRAEFIK_RANCHER_EXPOSED:-"false"}
TRAEFIK_RANCHER_HEALTHCHECK=${TRAEFIK_RANCHER_HEALTHCHECK:-"false"}
TRAEFIK_RANCHER_INTERVALPOLL=${TRAEFIK_RANCHER_INTERVALPOLL:-"false"}
TRAEFIK_RANCHER_CONSTRAINTS=${TRAEFIK_RANCHER_CONSTRAINTS:-""}
TRAEFIK_RANCHER_OPTS=${TRAEFIK_RANCHER_OPTS:-""}
TRAEFIK_RANCHER_PREFIX=${TRAEFIK_RANCHER_PREFIX:-"/2016-07-29"}
TRAEFIK_USAGE_ENABLE=${TRAEFIK_USAGE_ENABLE:-"false"}

#
# Converts 1.2.3.4/xx,5.6.7.8 to ["1.2.3.4/xx","5.6.7.8"]
#
csv2array() {
    IPS="$1"
    FIRST="TRUE"
    IFS=" ,"
    echo -n "["
    for IP in $IPS ; do
        if [ x"$FIRST" != x"TRUE" ] ; then
            echo -n ","
        fi
        echo -n "\"$IP\""
        FIRST="FALSE"
    done
    echo -n "]"
    unset $IFS
}

TRAEFIK_ENTRYPOINTS_OPTS="\
[entryPoints]
"

TRAEFIK_ENTRYPOINTS_HTTP="\
  [entryPoints.http]
    address = \":${TRAEFIK_HTTP_PORT}\"
    [entryPoints.http.transport]
      [entryPoints.http.transport.respondingTimeouts]
        readTimeout = \"${TRAEFIK_TIMEOUT_READ}s\"
        writeTimeout = \"${TRAEFIK_TIMEOUT_WRITE}s\"
        idleTimeout = \"${TRAEFIK_TIMEOUT_IDLE}s\"
      [entryPoints.http.transport.lifecycle]
        requestAcceptGraceTimeout = \"${TRAEFIK_TIMEOUT_ACCEPT}s\"
        graceTimeOut = \"${TRAEFIK_TIMEOUT_GRACE}s\"
"

# Default ssl key. Could be overwritten with TRAEFIK_SSL_KEY env var.
TRAEFIK_SSL_KEY=${TRAEFIK_SSL_KEY:-"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"}

# Default ssl key. Could be overwritten with TRAEFIK_SSL_CERT env var.
TRAEFIK_SSL_CRT=${TRAEFIK_SSL_CRT:-"-----BEGIN CERTIFICATE-----
MIIFpzCCA4+gAwIBAgIJAMLzkyNyXM/VMA0GCSqGSIb3DQEBCwUAMGoxCzAJBgNV
BAYTAkVTMQ8wDQYDVQQIDAZNYWRyaWQxDzANBgNVBAcMBk1hZHJpZDEVMBMGA1UE
CgwMVHJhZWZpay10ZXN0MRAwDgYDVQQLDAdUZXN0aW5nMRAwDgYDVQQDDAcqLmxv
Y2FsMB4XDTE2MDYwNzEwMjMzOFoXDTIxMDYwNzEwMjMzOFowajELMAkGA1UEBhMC
RVMxDzANBgNVBAgMBk1hZHJpZDEPMA0GA1UEBwwGTWFkcmlkMRUwEwYDVQQKDAxU
cmFlZmlrLXRlc3QxEDAOBgNVBAsMB1Rlc3RpbmcxEDAOBgNVBAMMByoubG9jYWww
ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDJKQhm+Cy+JLz85eUaYe6t
w2Qpl5YyH5zDPcpnFuBsWmqkG6MEw8vzQu3z85sp9VnNpzwkKVARuZCIY5nC4Jt2
bNVLxuY6VxpbF07ZVge4tb8675ZUga81O2km++iq3GKpYSyHYXOtivGmqOiqHAXH
k32CmsCP6LjwB2BSHKiQjwCaulHoHbieiN8+v5x7OyqI+gL6zFApLN9P+SLfeVr8
UDK1QlJnrf382eQBXtoEuBzvSnqAK1lodX44wE3qN608DafwulO3OyBY6n0JS/86
SX4KbPUZt07Ef0g0a17wXuUhWWZdcC+e/KNk0wo9k/dDb8wvqhU1K18A1M0ap8LM
Ii1V8rK5d93q2mSe+1qhinrmwuE6/ELDWVz4ggTybwxCIXnYYt85myvgW2HLyGDx
bAl6AG6RbV2KTxEgVLQslH2qxfiaCxLomwXjUpzmjVLkd1otPg++rnRIDFIwcUcb
vqkA0lYRoqshUwrP8Atzryux+wJzNDNPFWKgbECfploD60/sxbijvVm8LGI2z8x2
UK+gHMxz1zvG8zKbjwJRXhL5vTx+aKxHh4v4a89i5dR6GFFAU4OMJ/M9/05/Tyez
anX2dUdH+0/1PGnxq2cKxsNSM3t57GCeRQiJXK4RZw3JG0NEml7K3R/Q5WewdHYn
bYMi7/c3cg95QlGMYvaebQIDAQABo1AwTjAdBgNVHQ4EFgQUzzBk0Sf/aGcO1z/H
qf5YmlCVYI8wHwYDVR0jBBgwFoAUzzBk0Sf/aGcO1z/Hqf5YmlCVYI8wDAYDVR0T
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAc6B5m9WWCHXPXOJNRnUuxC63ETNS
Ir/IbkMV8TYaovUr0tlf5TIPFCQ7eqNJcTb2aAQO3w+F0Wddc5i1WSbkCUV75x7L
iHmktwO81XS9XZlkpo4+O2IU8oKhwF70bPn/wM5Kyb0aykJAdDSpwRagcYn7Vdk7
U/C4MiEaXlnvc9CTNWT+NoI4IEaKntimqS+k193Yxo9fOqmo2v0eiuAeOy9PJvLo
qBBh9Tz7yuUdOLbUWsqXaFL2VBecKehorS/zrh8CbNuIG/9HEjVWOFAONoqWX7Qz
77QSVJVhgxk+N/agY9v0ov66W0vEyhHndvdHQg70feyVL8L9g82Uis3a2wA/82Zp
nxRNoVddro0wQDMWEf5sGHZXoG+aY/CsWT35A5NHdMaVirPDvE38GhxBwDmk8uo1
NaswgbCwZHU30vvLPvHumfUFYWurPtkrZ2gqSqxewwgXOo9m14FxQhE9U7ax5ZSY
ji6JqNHQk8F1scCn9L0iX7yDcCFPRvzvB2mOGRGdVWrk6dx3XR0jpLOyEausM07a
rsdpTYCWNsbLafsTGbIWc/ddhb9SN+fnWLDpNSXKN9IU5tzUuA60ZP4lfPun26L8
7l4ZF1JEN6lui55Z0Vfo0vB7oGVT64SLiigbTDl1LrrusqOpPXOPzvNEfUQ5Zhhi
x8NPFRMB44AWyLI=
-----END CERTIFICATE-----"}

# Write key and cert files if not already exist
if [ ! -e ${TRAEFIK_SSL_KEY_FILE} ]; then
  echo "${TRAEFIK_SSL_KEY}" > ${TRAEFIK_SSL_KEY_FILE}
fi
if [ ! -e ${TRAEFIK_SSL_CRT_FILE} ]; then
  echo "${TRAEFIK_SSL_CRT}" > ${TRAEFIK_SSL_CRT_FILE}
fi

if [ "${TRAEFIK_HTTPS_ENABLE}" == "true" ] || [ "${TRAEFIK_HTTPS_ENABLE}" == "only" ]; then
  TRAEFIK_ENTRYPOINTS_HTTPS="\
  [entryPoints.https]
    address = \":${TRAEFIK_HTTPS_PORT}\"
    [entryPoints.https.transport]
      [entryPoints.https.transport.respondingTimeouts]
        readTimeout = \"${TRAEFIK_TIMEOUT_READ}s\"
        writeTimeout = \"${TRAEFIK_TIMEOUT_WRITE}s\"
        idleTimeout = \"${TRAEFIK_TIMEOUT_IDLE}s\"
      [entryPoints.https.transport.lifecycle]
        requestAcceptGraceTimeout = \"${TRAEFIK_TIMEOUT_ACCEPT}s\"
        graceTimeOut = \"${TRAEFIK_TIMEOUT_GRACE}s\"
"
  filelist=`ls -1 ${TRAEFIK_SSL_PATH}/*.key | rev | cut -d"." -f2- | rev`
  RC=`echo $?`

  if [ $RC -eq 0 ]; then
      for i in $filelist; do
          if [ -f "$i.crt" ]; then
      TRAEFIK_SSL_OPTS=$TRAEFIK_SSL_OPTS"
[[tls.certificates]]
  certFile = \"${i}.crt\"
  keyFile = \"${i}.key\"
"
          fi
      done
  fi

  TRAEFIK_HTTPS_OPTS="
[tls.stores]
  [tls.stores.default]
    [tls.stores.default.defaultCertificate]
      certFile = \"${TRAEFIK_SSL_CRT_FILE}\"
      keyFile  = \"${TRAEFIK_SSL_KEY_FILE}\"
[tls.options]
  [tls.options.default]
    minVersion = \"${TRAEFIK_HTTPS_MIN_TLS}\"
"
fi

if [ "${TRAEFIK_ADMIN_ENABLE}" == "true" ]; then
    TRAEFIK_ENTRYPOINTS_ADMIN="\
  [entryPoints.traefik]
    address = \":${TRAEFIK_ADMIN_PORT}\"
"
    TRAEFIK_ENTRYPOINTS_OPTS=${TRAEFIK_ENTRYPOINTS_OPTS}${TRAEFIK_ENTRYPOINTS_ADMIN}
    TRAEFIK_ADMIN_API="\
[api]
  dashboard = true
  debug = ${TRAEFIK_DEBUG}
  insecure = true

[ping]
  entryPoint = \"traefik\"
"
fi

if [ "${TRAEFIK_HTTPS_ENABLE}" == "true" ]; then
    TRAEFIK_ENTRYPOINTS_OPTS=${TRAEFIK_ENTRYPOINTS_OPTS}${TRAEFIK_ENTRYPOINTS_HTTP}${TRAEFIK_ENTRYPOINTS_HTTPS}
elif [ "${TRAEFIK_HTTPS_ENABLE}" == "only" ]; then
    TRAEFIK_ENTRYPOINTS_OPTS=${TRAEFIK_ENTRYPOINTS_OPTS}${TRAEFIK_ENTRYPOINTS_HTTP}${TRAEFIK_ENTRYPOINTS_HTTPS}
cat << EOF > ${SERVICE_HOME}/dynamic/global_http_redirect.toml
[http.routers]
  [http.routers.global-https-redirect]
    entryPoints = ["http"]
    middlewares = ["global-https-redirect"]
    rule = "HostRegexp(\`{any:.+}\`)"
    service = "global-https-redirect-noop"
[http.services]
  # noop service, the URL will be never called
  [http.services.global-https-redirect-noop.loadBalancer]
    [[http.services.global-https-redirect-noop.loadBalancer.servers]]
      url = "http://127.0.0.1:1337"
[http.middlewares]
  [http.middlewares.global-https-redirect.redirectScheme]
    scheme = "https"
    permanent = true
EOF
else
    TRAEFIK_ENTRYPOINTS_OPTS=${TRAEFIK_ENTRYPOINTS_OPTS}${TRAEFIK_ENTRYPOINTS_HTTP}
fi

if [ "${TRAEFIK_RANCHER_ENABLE}" == "true" ]; then
    TRAEFIK_RANCHER_OPTS="\
  [providers.rancher]
    watch = true
    refreshSeconds = ${TRAEFIK_RANCHER_REFRESH}
    exposedByDefault = ${TRAEFIK_RANCHER_EXPOSED}
    enableServiceHealthFilter = ${TRAEFIK_RANCHER_HEALTHCHECK}
    intervalPoll = ${TRAEFIK_RANCHER_INTERVALPOLL}
    prefix = \"${TRAEFIK_RANCHER_PREFIX}\"
"
    if [ "${TRAEFIK_RANCHER_CONSTRAINTS}" != "" ]; then
        TRAEFIK_RANCHER_OPTS=${TRAEFIK_RANCHER_OPTS}"\
    constraints = [ ${TRAEFIK_RANCHER_CONSTRAINTS} ]
"
    fi
fi


cat << EOF > ${SERVICE_HOME}/dynamic/tls.toml
${TRAEFIK_HTTPS_OPTS}
${TRAEFIK_SSL_OPTS}
EOF

cat << EOF > ${SERVICE_HOME}/etc/traefik.toml
# traefik.toml
[global]
  sendAnonymousUsage = ${TRAEFIK_USAGE_ENABLE}

[log]
  level = "${TRAEFIK_LOG_LEVEL}"
  filePath = "${TRAEFIK_LOG_FILE}"

[accessLog]
  filePath = "${TRAEFIK_ACCESS_FILE}"

[serversTransport]
  insecureSkipVerify = ${TRAEFIK_INSECURE_SKIP}
  [serversTransport.forwardingTimeouts]
    dialTimeout = "${TRAEFIK_TIMEOUT_DIAL}s"
    responseHeaderTimeout = "${TRAEFIK_TIMEOUT_HEADER}s"

${TRAEFIK_ENTRYPOINTS_OPTS}
${TRAEFIK_ADMIN_API}
[providers]
  [providers.file]
    directory = "${SERVICE_HOME}/dynamic"
    watch = true
${TRAEFIK_RANCHER_OPTS}
EOF
