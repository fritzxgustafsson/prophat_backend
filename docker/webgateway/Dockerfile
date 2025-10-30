FROM containers.intersystems.com/intersystems/webgateway:latest-cd

COPY config/CSP.conf /opt/iris/CSP.conf
COPY config/CSP.ini /opt/iris/CSP.ini

ENV ISC_CSP_CONF_FILE="/opt/iris/CSP.conf"
ENV ISC_CSP_INI_FILE="/opt/iris/CSP.ini"
ENV ISC_DATA_DIRECTORY="/persistent/iris"